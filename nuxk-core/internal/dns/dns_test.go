package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// respond builds an answer to q: A records (a pointer back to the question's
// name), or NXDOMAIN when there are none.
func respond(q []byte, ips ...string) []byte {
	end, err := questionEnd(q)
	if err != nil {
		return nil
	}
	m := append([]byte{}, q[:end]...)
	m[2] = 0x80 | (q[2] & 0x01)
	m[3] = 0x80
	if len(ips) == 0 {
		m[3] |= RcodeNXDomain
	}
	binary.BigEndian.PutUint16(m[6:8], uint16(len(ips)))
	binary.BigEndian.PutUint16(m[8:10], 0)
	binary.BigEndian.PutUint16(m[10:12], 0)
	for _, ip := range ips {
		a := netip.MustParseAddr(ip).As4()
		m = append(m, 0xC0, 0x0C, 0, TypeA, 0, 1, 0, 0, 0, 60, 0, 4)
		m = append(m, a[:]...)
	}
	return m
}

// zone: what the fake resolver behind the tunnel knows.
var zone = map[string][]string{
	"cloudflare.com": {"104.16.132.229"},
	"rutor.info":     {"104.21.8.8"},
	"flibusta.is":    {"104.21.9.9"},
}

func bigZone() []string {
	var ips []string
	for i := 1; i <= 80; i++ {
		ips = append(ips, "203.0.113."+strconv.Itoa(i))
	}
	return ips
}

// dohServer answers RFC 8484 POSTs from zone; it counts the questions.
func dohServer(t *testing.T) (*httptest.Server, func() int) {
	t.Helper()
	n := 0
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad", 400)
			return
		}
		q, _ := io.ReadAll(r.Body)
		if len(q) < 2 || q[0] != 0 || q[1] != 0 {
			http.Error(w, "id must be 0", 400)
			return
		}
		mu.Lock()
		n++
		mu.Unlock()
		name := QName(q)
		ips := zone[name]
		if name == "big.example" {
			ips = bigZone()
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(respond(q, ips...))
	}))
	t.Cleanup(srv.Close)
	return srv, func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

type failRT struct{}

func (failRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("tunnel down")
}

func freeAddr(t *testing.T) string {
	t.Helper()
	for i := 0; i < 20; i++ {
		u, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := u.LocalAddr().String()
		u.Close()
		if l, err := net.Listen("tcp", addr); err == nil {
			l.Close()
			return addr
		}
	}
	t.Fatal("no free port")
	return ""
}

type fakeHook struct {
	mu    sync.Mutex
	calls []string
	err   error
	onAtt func()
}

func (h *fakeHook) Attach(_ context.Context, addr string) error {
	h.mu.Lock()
	h.calls = append(h.calls, "attach "+addr)
	f := h.onAtt
	h.mu.Unlock()
	if f != nil {
		f()
	}
	return h.err
}

func (h *fakeHook) Detach(_ context.Context, addr string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "detach "+addr)
	return nil
}

func (h *fakeHook) log() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.calls, "|")
}

type memStore map[string]any

func (m memStore) LoadJSON(string, any) error     { return nil }
func (m memStore) SaveJSON(n string, v any) error { m[n] = v; return nil }

func newService(t *testing.T, srv *httptest.Server, o Options) *Service {
	t.Helper()
	o.Listen = freeAddr(t)
	o.Resolvers = []Resolver{{ID: "t", Name: "Test", URL: srv.URL + "/dns-query"}}
	if o.Transport == nil {
		o.Transport = func(p Path) http.RoundTripper {
			if p.Name == PathDirect {
				return srv.Client().Transport
			}
			return failRT{}
		}
	}
	s := New(o, memStore{})
	t.Cleanup(s.stop)
	return s
}

func ask(t *testing.T, network, server, name string) []byte {
	t.Helper()
	resp, err := askErr(network, server, name)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func askErr(network, server, name string) ([]byte, error) {
	q, _ := Query(0x4242, name, TypeA)
	c, err := net.DialTimeout(network, server, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if network == "tcp" {
		q = append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	if network == "tcp" {
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(l[:]))
		_, err := io.ReadFull(c, resp)
		return resp, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	return buf[:n], err
}

// A query in over UDP or TCP, out as DoH — through the tunnel if it's up,
// straight when it isn't — and the asker's ID back in the answer (asked
// again: from the cache).
func TestForwarder(t *testing.T) {
	srv, n := dohServer(t)
	s := newService(t, srv, Options{Paths: func() []Path { return []Path{{Name: "vless", Iface: "opkgtun1"}} }})
	if err := s.start(); err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"udp", "tcp"} {
		resp := ask(t, network, s.o.Listen, "cloudflare.com")
		a, err := Parse(resp)
		if err != nil || resp[0] != 0x42 || resp[1] != 0x42 || len(a.Addrs) != 1 || a.Addrs[0].String() != "104.16.132.229" {
			t.Fatalf("%s: %v %+v % x", network, err, a, resp[:2])
		}
	}
	st := s.Status()
	if st.Queries != 2 || st.LastPath != PathDirect || n() != 1 || st.Cache.Hits != 1 {
		t.Fatalf("status %+v, doh asked %d (the second from the cache)", st, n())
	}
	var vless PathStat
	for _, p := range st.Paths {
		if p.Name == "vless" {
			vless = p
		}
	}
	if !vless.Up || vless.Failed != 1 || !strings.Contains(vless.LastErr, "tunnel down") {
		t.Fatalf("the tunnel was tried first: %+v", vless)
	}

	// too big for UDP: truncated, the whole answer over TCP
	if resp := ask(t, "udp", s.o.Listen, "big.example"); resp[2]&0x02 == 0 || len(resp) > 512 {
		t.Fatalf("UDP answer not truncated: %d bytes", len(resp))
	}
	if a, err := Parse(ask(t, "tcp", s.o.Listen, "big.example")); err != nil || len(a.Addrs) != 80 {
		t.Fatalf("TCP: %v %d", err, len(a.Addrs))
	}
	// «no such site» passes through as it is
	if a, _ := Parse(ask(t, "udp", s.o.Listen, "nope.example")); a.Rcode != RcodeNXDomain {
		t.Fatalf("rcode %d", a.Rcode)
	}
}

func TestServFailWhenNothingAnswers(t *testing.T) {
	srv, _ := dohServer(t)
	s := newService(t, srv, Options{Transport: func(Path) http.RoundTripper { return failRT{} }})
	if err := s.start(); err != nil {
		t.Fatal(err)
	}
	resp := ask(t, "udp", s.o.Listen, "cloudflare.com")
	if resp[3]&0x0F != RcodeServFail || resp[0] != 0x42 {
		t.Fatalf("% x", resp[:4])
	}
	if s.Status().Failed != 1 {
		t.Fatal("not counted")
	}
}

// fakeProxy stands for the router's DNS proxy: it answers cloudflare.com
// itself and passes nuxk's test question on to the forwarder, as a proxy with
// nuxk among its servers does. dead: it doesn't answer at all.
func fakeProxy(t *testing.T, forwarder func() string, dead *bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte{}, buf[:n]...)
			if *dead {
				continue
			}
			name := QName(q)
			var resp []byte
			if strings.HasSuffix(name, ".nuxk-check.example.com") {
				if c, err := net.Dial("udp", forwarder()); err == nil {
					_ = c.SetDeadline(time.Now().Add(3 * time.Second))
					_, _ = c.Write(q)
					b := make([]byte, 4096)
					if m, err := c.Read(b); err == nil {
						resp = b[:m]
					}
					c.Close()
				}
			} else {
				resp = respond(q, zone[name]...)
			}
			if resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func TestEnableAttachesAndChecks(t *testing.T) {
	srv, _ := dohServer(t)
	dead := false
	var s *Service
	h := &fakeHook{}
	proxy := fakeProxy(t, func() string { return s.o.Listen }, &dead)
	s = newService(t, srv, Options{Hook: h, RouterDNS: proxy})
	st, err := s.SetSettings(context.Background(), Settings{Enabled: true, Via: ViaAuto})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Settings.Enabled || !st.Running || !st.Attached || !st.Consulted || h.log() != "attach "+s.o.Listen {
		t.Fatalf("status %+v, hook %q", st, h.log())
	}
	st, err = s.SetSettings(context.Background(), Settings{Enabled: false, Via: ViaAuto})
	if err != nil || st.Running || st.Attached || st.Settings.Enabled || !strings.HasSuffix(h.log(), "|detach "+s.o.Listen) {
		t.Fatalf("off: %v %+v %q", err, st, h.log())
	}
}

// The router stops answering once nuxk is added: taken back at once, all as
// it was.
func TestEnableRevertsWhenRouterDNSBreaks(t *testing.T) {
	srv, _ := dohServer(t)
	dead := false
	var s *Service
	h := &fakeHook{onAtt: func() { dead = true }}
	proxy := fakeProxy(t, func() string { return s.o.Listen }, &dead)
	s = newService(t, srv, Options{Hook: h, RouterDNS: proxy})
	st, err := s.SetSettings(context.Background(), Settings{Enabled: true})
	if err == nil || !strings.Contains(err.Error(), "отключил обратно") {
		t.Fatalf("err %v", err)
	}
	if st.Settings.Enabled || st.Attached || st.Running || h.log() != "attach "+s.o.Listen+"|detach "+s.o.Listen {
		t.Fatalf("status %+v, hook %q", st, h.log())
	}
}

func TestEnableRefuses(t *testing.T) {
	srv, _ := dohServer(t)
	// no Keenetic
	s := newService(t, srv, Options{})
	if _, err := s.SetSettings(context.Background(), Settings{Enabled: true}); !errors.Is(err, ErrNoHook) {
		t.Fatalf("no hook: %v", err)
	}
	// no way out answers: the router isn't touched
	h := &fakeHook{}
	s = newService(t, srv, Options{Hook: h, Transport: func(Path) http.RoundTripper { return failRT{} }})
	if _, err := s.SetSettings(context.Background(), Settings{Enabled: true}); err == nil || h.log() != "" {
		t.Fatalf("err %v, hook %q", err, h.log())
	}
	if _, err := s.SetSettings(context.Background(), Settings{Via: "tor"}); !errors.Is(err, ErrBadSettings) {
		t.Fatalf("bad via: %v", err)
	}
}

// Nothing answers three minutes running: taken back from the proxy; answers
// again: added back.
func TestSuspendAndResume(t *testing.T) {
	srv, _ := dohServer(t)
	down := false
	h := &fakeHook{}
	dead := false
	var s *Service
	proxy := fakeProxy(t, func() string { return s.o.Listen }, &dead)
	s = newService(t, srv, Options{Hook: h, RouterDNS: proxy, Transport: func(Path) http.RoundTripper {
		return rtFunc(func(r *http.Request) (*http.Response, error) {
			if down {
				return nil, errors.New("down")
			}
			return srv.Client().Transport.RoundTrip(r)
		})
	}})
	ctx := context.Background()
	if _, err := s.SetSettings(ctx, Settings{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	down = true
	for i := 0; i < 3; i++ {
		s.tick(ctx)
	}
	if st := s.Status(); st.Attached || !st.Suspended || !st.Settings.Enabled || st.Error == "" {
		t.Fatalf("suspended: %+v", st)
	}
	down = false
	s.tick(ctx)
	if st := s.Status(); !st.Attached || st.Suspended || st.Error != "" {
		t.Fatalf("resumed: %+v", st)
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The check: the router hands out one stub for two blocked sites, the plain
// resolver says they don't exist; the tunnel knows better.
func TestCheck(t *testing.T) {
	srv, _ := dohServer(t)
	stub := func(q []byte) []byte {
		switch QName(q) {
		case "rutor.info", "flibusta.is":
			return respond(q, "95.167.13.50")
		}
		return respond(q, zone[QName(q)]...)
	}
	router := udpServer(t, stub)
	plain := udpServer(t, func(q []byte) []byte { return respond(q) }) // NXDOMAIN for everything
	s := newService(t, srv, Options{RouterDNS: router, PlainDNS: plain, Domains: func() []string {
		return []string{"cloudflare.com", "*.bad", "rutor.info"}
	}})
	c := s.Check(context.Background(), nil)
	if c.Path != PathDirect || len(c.Items) != 4 {
		t.Fatalf("%+v", c)
	}
	got := map[string]CheckItem{}
	for _, it := range c.Items {
		got[it.Domain] = it
	}
	if got["rutor.info"].RouterVerdict != VerdictSpoofed || got["flibusta.is"].RouterVerdict != VerdictSpoofed ||
		got["cloudflare.com"].RouterVerdict != VerdictOK || got["rezka.ag"].RouterVerdict != VerdictOK {
		t.Fatalf("router verdicts: %+v", c.Items)
	}
	if got["rutor.info"].PlainVerdict != VerdictSpoofed || c.Router != 2 || c.Plain != 3 {
		t.Fatalf("counts: router %d plain %d, %+v", c.Router, c.Plain, c.Items)
	}
}

func udpServer(t *testing.T, answer func([]byte) []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := answer(append([]byte{}, buf[:n]...)); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// On the LAN address the forwarder answers the router only, not devices.
func TestAllowed(t *testing.T) {
	s := New(Options{Listen: "192.168.2.1:53053"}, nil)
	for ip, want := range map[string]bool{"192.168.2.1": true, "127.0.0.1": true, "192.168.2.37": false, "10.0.0.5": false} {
		if s.Allowed(net.ParseIP(ip)) != want {
			t.Errorf("%s: %v", ip, !want)
		}
	}
	if !New(Options{Listen: "0.0.0.0:53053"}, nil).Allowed(net.ParseIP("192.168.2.37")) {
		t.Error("listening everywhere is the person's choice: everyone may ask")
	}
}
