package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type rr struct {
	typ   uint16
	ttl   uint32
	rdata []byte
}

// msgWith: an answer to q with the given sections (names point back at the
// question's).
func msgWith(q []byte, rcode byte, an, ns, ar []rr) []byte {
	end, _ := questionEnd(q)
	m := append([]byte{}, q[:end]...)
	m[2] = 0x80 | (q[2] & 0x01)
	m[3] = 0x80 | rcode
	binary.BigEndian.PutUint16(m[6:8], uint16(len(an)))
	binary.BigEndian.PutUint16(m[8:10], uint16(len(ns)))
	binary.BigEndian.PutUint16(m[10:12], uint16(len(ar)))
	for _, sec := range [][]rr{an, ns, ar} {
		for _, r := range sec {
			if r.typ == typeOPT {
				m = append(m, 0) // the root
			} else {
				m = append(m, 0xC0, 0x0C)
			}
			m = binary.BigEndian.AppendUint16(m, r.typ)
			m = binary.BigEndian.AppendUint16(m, 1)
			m = binary.BigEndian.AppendUint32(m, r.ttl)
			m = binary.BigEndian.AppendUint16(m, uint16(len(r.rdata)))
			m = append(m, r.rdata...)
		}
	}
	return m
}

func soa(minimum uint32) []byte {
	b := []byte{0, 0} // mname, rname: the root
	for _, v := range []uint32{2026092901, 7200, 3600, 1209600, minimum} {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return b
}

func aRR(ttl uint32, ip ...byte) rr { return rr{TypeA, ttl, ip} }

// withOPT: q with an EDNS record (do: DNSSEC answers wanted).
func withOPT(q []byte, do bool) []byte {
	m := append([]byte{}, q...)
	binary.BigEndian.PutUint16(m[10:12], binary.BigEndian.Uint16(m[10:12])+1)
	flags := byte(0)
	if do {
		flags = 0x80
	}
	return append(m, 0, 0, typeOPT, 0x04, 0xD0, 0, 0, flags, 0, 0, 0)
}

func mustQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	q, err := Query(0x1234, name, qtype)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestCacheKey(t *testing.T) {
	q := mustQuery(t, "Example.COM", TypeA)
	k := cacheKey(q)
	if k == "" || k != cacheKey(mustQuery(t, "example.com", TypeA)) {
		t.Fatal("the name's case must not matter")
	}
	differ := map[string][]byte{
		"type": mustQuery(t, "example.com", TypeAAAA),
		"edns": withOPT(q, false),
		"do":   withOPT(q, true),
	}
	cd := append([]byte{}, q...)
	cd[3] |= 0x10
	differ["cd"] = cd
	norec := append([]byte{}, q...)
	norec[2] &^= 0x01
	differ["rd"] = norec
	seen := map[string]string{k: "plain"}
	for what, m := range differ {
		mk := cacheKey(m)
		if mk == "" {
			t.Fatalf("%s: not kept", what)
		}
		if other, dup := seen[mk]; dup {
			t.Fatalf("%s and %s share a key", what, other)
		}
		seen[mk] = what
	}
	notKept := map[string][]byte{
		"response": respond(q, "1.2.3.4"),
		"any":      mustQuery(t, "example.com", typeANY),
		"axfr":     mustQuery(t, "example.com", typeAXFR),
		"short":    q[:10],
	}
	opcode := append([]byte{}, q...)
	opcode[2] |= 0x10 // STATUS
	notKept["opcode"] = opcode
	two := append([]byte{}, q...)
	two[5] = 2
	notKept["two questions"] = two
	for what, m := range notKept {
		if cacheKey(m) != "" {
			t.Errorf("%s: kept", what)
		}
	}
}

func TestParseEntry(t *testing.T) {
	q := mustQuery(t, "example.com", TypeA)
	k := cacheKey(q)
	cases := []struct {
		name string
		resp []byte
		ttl  uint32 // 0: not kept
	}{
		{"the shortest TTL", msgWith(q, RcodeNoError, []rr{aRR(300, 1, 1, 1, 1), aRR(60, 1, 1, 1, 2)}, nil, nil), 60},
		{"a day at most", msgWith(q, RcodeNoError, []rr{aRR(7*86400, 1, 1, 1, 1)}, nil, nil), maxTTL},
		{"zero TTL", msgWith(q, RcodeNoError, []rr{aRR(0, 1, 1, 1, 1)}, nil, nil), 0},
		{"no such name: the SOA's minimum", msgWith(q, RcodeNXDomain, nil, []rr{{typeSOA, 3600, soa(120)}}, nil), 120},
		{"no such name: five minutes at most", msgWith(q, RcodeNXDomain, nil, []rr{{typeSOA, 3600, soa(900)}}, nil), maxNegTTL},
		{"no such type: the SOA", msgWith(q, RcodeNoError, nil, []rr{{typeSOA, 60, soa(900)}}, nil), 60},
		{"no such name, no SOA", msgWith(q, RcodeNXDomain, nil, nil, nil), 0},
		{"SERVFAIL", msgWith(q, RcodeServFail, nil, nil, nil), 0},
		{"EDNS doesn't count", msgWith(q, RcodeNoError, []rr{aRR(60, 1, 1, 1, 1)}, nil, []rr{{typeOPT, 0, nil}}), 60},
	}
	for _, c := range cases {
		e := parseEntry(k, q, c.resp)
		switch {
		case c.ttl == 0 && e != nil:
			t.Errorf("%s: kept for %d s", c.name, e.ttl)
		case c.ttl != 0 && e == nil:
			t.Errorf("%s: not kept", c.name)
		case c.ttl != 0 && e.ttl != c.ttl:
			t.Errorf("%s: ttl %d, want %d", c.name, e.ttl, c.ttl)
		}
	}
	tc := msgWith(q, RcodeNoError, []rr{aRR(60, 1, 1, 1, 1)}, nil, nil)
	tc[2] |= 0x02
	if parseEntry(k, q, tc) != nil {
		t.Error("a truncated answer kept")
	}
	if parseEntry(k, q, respond(mustQuery(t, "example.org", TypeA), "1.1.1.1")) != nil {
		t.Error("an answer to another question kept")
	}
}

// Handed back: the asker's ID and spelling, the TTLs counted down, EDNS
// flags untouched; an expired answer with 30 s.
func TestEntryReply(t *testing.T) {
	q := withOPT(mustQuery(t, "example.com", TypeA), true)
	resp := msgWith(q, RcodeNoError, []rr{aRR(60, 1, 1, 1, 1), aRR(300, 1, 1, 1, 2)}, nil, []rr{{typeOPT, 0x8000, nil}})
	e := parseEntry(cacheKey(q), q, resp)
	t0 := time.Unix(1_800_000_000, 0)
	e.stored = t0
	asker := withOPT(mustQuery(t, "eXaMpLe.CoM", TypeA), true)
	asker[0], asker[1] = 0xBE, 0xEF
	m := e.reply(asker, t0.Add(25*time.Second), false)
	if m[0] != 0xBE || m[1] != 0xEF || QName(m) != "example.com" || !strings.Contains(string(m), "eXaMpLe") {
		t.Fatalf("id or name: % x", m[:20])
	}
	ttls := func(m []byte) []uint32 {
		var out []uint32
		for _, off := range e.ttls {
			out = append(out, binary.BigEndian.Uint32(m[off:off+4]))
		}
		return out
	}
	if got := ttls(m); len(got) != 2 || got[0] != 35 || got[1] != 275 {
		t.Fatalf("ttls %v", got)
	}
	if binary.BigEndian.Uint32(m[len(m)-6:len(m)-2]) != 0x8000 {
		t.Fatalf("OPT's flags touched: % x", m[len(m)-11:])
	}
	if got := ttls(e.reply(asker, t0.Add(time.Hour), true)); got[0] != staleTTL || got[1] != staleTTL {
		t.Fatalf("stale ttls %v", got)
	}
}

func TestCacheLimits(t *testing.T) {
	c := newCache()
	t0 := time.Unix(1_800_000_000, 0)
	put := func(name string, size int) {
		q := mustQuery(t, name, TypeA)
		e := parseEntry(cacheKey(q), q, msgWith(q, RcodeNoError, []rr{aRR(60, 1, 1, 1, 1)}, nil, nil))
		if size > 0 {
			e.size = size
		}
		c.put(e, t0)
	}
	put("keep.example", 0)
	for i := 0; i < cacheMaxEntries+100; i++ {
		put("n"+strconv.Itoa(i)+".example", 0)
		if i%1000 == 0 { // used now and then: stays
			c.get(cacheKey(mustQuery(t, "keep.example", TypeA)), t0)
		}
	}
	if st := c.stats(); st.Entries != cacheMaxEntries || st.Bytes > cacheMaxBytes {
		t.Fatalf("%+v", st)
	}
	if e, _ := c.get(cacheKey(mustQuery(t, "keep.example", TypeA)), t0); e == nil {
		t.Fatal("a name in use evicted")
	}
	if e, _ := c.get(cacheKey(mustQuery(t, "n0.example", TypeA)), t0); e != nil {
		t.Fatal("the oldest stayed")
	}
	for i := 0; i < 10; i++ {
		put("big"+strconv.Itoa(i)+".example", cacheMaxBytes/4)
	}
	if st := c.stats(); st.Bytes > cacheMaxBytes {
		t.Fatalf("bytes %d", st.Bytes)
	}
	c.flush()
	if st := c.stats(); st.Entries != 0 || st.Bytes != 0 {
		t.Fatalf("flushed: %+v", st)
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func ttlOf(t *testing.T, resp []byte) uint32 {
	t.Helper()
	ttl, ok := ttlIn(resp)
	if !ok {
		t.Fatalf("no answer: % x", resp)
	}
	return ttl
}

// ttlIn: the first answer record's TTL.
func ttlIn(resp []byte) (uint32, bool) {
	off, err := questionEnd(resp)
	if err != nil || binary.BigEndian.Uint16(resp[6:8]) == 0 {
		return 0, false
	}
	if off, err = skipName(resp, off); err != nil || off+8 > len(resp) {
		return 0, false
	}
	return binary.BigEndian.Uint32(resp[off+4 : off+8]), true
}

// Asked again: from the cache, the TTL counted down; expired: the resolvers
// again. «No such name» without the zone's SOA isn't kept.
func TestCacheAnswers(t *testing.T) {
	srv, n := dohServer(t)
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	s := newService(t, srv, Options{Clock: clk.Now})
	if err := s.start(); err != nil {
		t.Fatal(err)
	}
	if ttlOf(t, ask(t, "udp", s.o.Listen, "cloudflare.com")) != 60 {
		t.Fatal("first answer")
	}
	clk.Add(20 * time.Second)
	resp := ask(t, "tcp", s.o.Listen, "CloudFlare.com")
	if ttlOf(t, resp) != 40 || n() != 1 || !strings.Contains(string(resp), "CloudFlare") {
		t.Fatalf("from the cache: ttl %d, doh asked %d", ttlOf(t, resp), n())
	}
	clk.Add(41 * time.Second)
	if ttlOf(t, ask(t, "udp", s.o.Listen, "cloudflare.com")) != 60 || n() != 2 {
		t.Fatalf("expired: doh asked %d", n())
	}
	ask(t, "udp", s.o.Listen, "nope.example")
	ask(t, "udp", s.o.Listen, "nope.example")
	if n() != 4 {
		t.Fatalf("no SOA — not kept: doh asked %d", n())
	}
	st := s.Status().Cache
	if st.Hits != 1 || st.Misses != 4 || st.Entries != 1 || st.Bytes == 0 {
		t.Fatalf("%+v", st)
	}
	s.FlushCache()
	ask(t, "udp", s.o.Listen, "cloudflare.com")
	if n() != 5 {
		t.Fatalf("flushed: doh asked %d", n())
	}
	// turned off: every question goes out, the cache is forgotten
	if _, err := s.SetSettings(context.Background(), Settings{Via: ViaAuto, Cache: false}); err != nil {
		t.Fatal(err)
	}
	ask(t, "udp", s.o.Listen, "cloudflare.com")
	ask(t, "udp", s.o.Listen, "cloudflare.com")
	if st := s.Status(); n() != 7 || st.Cache.Entries != 0 || st.Settings.Cache {
		t.Fatalf("off: doh asked %d, %+v", n(), st.Cache)
	}
}

// No way out answers: an answer that expired within a day stands in, with
// 30 s; older than that — SERVFAIL.
func TestServeStale(t *testing.T) {
	srv, _ := dohServer(t)
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	var mu sync.Mutex
	down := false
	s := newService(t, srv, Options{Clock: clk.Now, Transport: func(Path) http.RoundTripper {
		return rtFunc(func(r *http.Request) (*http.Response, error) {
			mu.Lock()
			d := down
			mu.Unlock()
			if d {
				return nil, errors.New("down")
			}
			return srv.Client().Transport.RoundTrip(r)
		})
	}})
	if err := s.start(); err != nil {
		t.Fatal(err)
	}
	ask(t, "udp", s.o.Listen, "cloudflare.com")
	mu.Lock()
	down = true
	mu.Unlock()
	clk.Add(10 * time.Minute)
	resp := ask(t, "udp", s.o.Listen, "cloudflare.com")
	if a, err := Parse(resp); err != nil || a.Rcode != RcodeNoError || len(a.Addrs) != 1 || ttlOf(t, resp) != staleTTL {
		t.Fatalf("stale: %v %+v", err, a)
	}
	if st := s.Status(); st.Cache.Stale != 1 || st.Failed != 0 {
		t.Fatalf("%+v", st.Cache)
	}
	clk.Add(staleMax)
	if a, _ := Parse(ask(t, "udp", s.o.Listen, "cloudflare.com")); a.Rcode != RcodeServFail {
		t.Fatalf("a day later: rcode %d", a.Rcode)
	}
}

// A way out that hangs: the expired answer goes back without waiting it
// out; the answer, when it comes, is kept. Many asking at once — one question
// goes out.
func TestStaleWhileSlow(t *testing.T) {
	srv, n := dohServer(t)
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	gate := make(chan struct{})
	var mu sync.Mutex
	slow := false
	s := newService(t, srv, Options{Clock: clk.Now, Transport: func(Path) http.RoundTripper {
		return rtFunc(func(r *http.Request) (*http.Response, error) {
			mu.Lock()
			sl := slow
			mu.Unlock()
			if sl {
				select {
				case <-gate:
				case <-r.Context().Done():
					return nil, r.Context().Err()
				}
			}
			return srv.Client().Transport.RoundTrip(r)
		})
	}})
	s.staleWait = 50 * time.Millisecond
	if err := s.start(); err != nil {
		t.Fatal(err)
	}
	ask(t, "udp", s.o.Listen, "cloudflare.com")
	mu.Lock()
	slow = true
	mu.Unlock()
	clk.Add(2 * time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			resp, err := askErr("udp", s.o.Listen, "cloudflare.com")
			if ttl, ok := ttlIn(resp); err != nil || !ok || ttl != staleTTL || time.Since(t0) > 2*time.Second {
				t.Errorf("not stale in time: %v ttl %d after %v", err, ttl, time.Since(t0))
			}
		}()
	}
	wg.Wait()
	close(gate)
	waitFor(t, func() bool { return n() == 2 && len(s.inflightKeys()) == 0 })
	if ttlOf(t, ask(t, "udp", s.o.Listen, "cloudflare.com")) != 60 || n() != 2 {
		t.Fatalf("the late answer not kept: doh asked %d", n())
	}
}

// Names in use are asked again shortly before they expire; others aren't.
func TestRefresh(t *testing.T) {
	srv, n := dohServer(t)
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	s := newService(t, srv, Options{Clock: clk.Now})
	if err := s.start(); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.set.Enabled = true
	s.mu.Unlock()
	ask(t, "udp", s.o.Listen, "cloudflare.com")
	ask(t, "udp", s.o.Listen, "cloudflare.com") // in use: asked twice
	ask(t, "udp", s.o.Listen, "rutor.info")     // asked once
	clk.Add(30 * time.Second)
	s.refresh()
	if n() != 2 {
		t.Fatalf("refreshed too early: doh asked %d", n())
	}
	clk.Add(22 * time.Second) // 8 s left
	s.refresh()
	waitFor(t, func() bool { return len(s.inflightKeys()) == 0 && n() == 3 })
	if st := s.Status().Cache; st.Refreshed != 1 {
		t.Fatalf("%+v", st)
	}
	clk.Add(30 * time.Second) // the old answer would have expired
	if ttlOf(t, ask(t, "udp", s.o.Listen, "cloudflare.com")) != 30 || n() != 3 {
		t.Fatalf("not refreshed: doh asked %d", n())
	}
}

func (s *Service) inflightKeys() []string {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	var out []string
	for k := range s.inflight {
		out = append(out, k)
	}
	return out
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}
