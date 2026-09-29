package dns

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// TestLive asks the real resolvers: NUXK_DNS_LIVE=1, and NUXK_DNS_LIVE_IFACE
// names a tunnel's interface to go through (the WARP stand on the Pi). Off by
// default — it needs the internet.
func TestLive(t *testing.T) {
	if os.Getenv("NUXK_DNS_LIVE") == "" {
		t.Skip("NUXK_DNS_LIVE not set")
	}
	iface := os.Getenv("NUXK_DNS_LIVE_IFACE")
	s := New(Options{Listen: "127.0.0.1:0", Paths: func() []Path {
		if iface == "" {
			return nil
		}
		return []Path{{Name: "warp", Iface: iface}}
	}}, nil)
	for _, via := range []string{ViaAuto, ViaDirect} {
		s.set.Via = via
		for _, r := range Catalog {
			s.set.Resolvers = []string{r.ID}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			t0 := time.Now()
			a, err := s.lookup(ctx, "cloudflare.com")
			cancel()
			if err != nil || len(a.Addrs) == 0 {
				// straight to a resolver may be blocked by the provider: that's
				// what the tunnel is for — only the tunnel must always answer
				if via == ViaDirect || iface == "" {
					t.Logf("%-10s via %-6s blocked: %v", r.Name, via, err)
				} else {
					t.Errorf("%s via %s: %v %+v", r.Name, via, err, a)
				}
				continue
			}
			t.Logf("%-10s via %-6s path %-6s %v %s", r.Name, via, s.lastPath, a.Addrs, time.Since(t0).Round(time.Millisecond))
			want := PathDirect
			if via == ViaAuto && iface != "" {
				want = "warp"
			}
			if s.lastPath != want {
				t.Errorf("%s via %s went %s", r.Name, via, s.lastPath)
			}
		}
	}
	s.set = s.normal(Settings{Via: ViaAuto})
	if rd := os.Getenv("NUXK_DNS_LIVE_ROUTER"); rd != "" {
		s.o.RouterDNS = rd
	}
	c := s.Check(context.Background(), nil)
	t.Logf("check: reference via %s; router spoofed %d, plain spoofed %d", c.Path, c.Router, c.Plain)
	for _, it := range c.Items {
		t.Logf("  %-14s router %-8s %v %s | plain %-8s %v %s | truth %v", it.Domain,
			it.RouterVerdict, it.Router, it.RouterNote, it.PlainVerdict, it.Plain, it.PlainNote, it.Truth)
	}
}

// TestLiveCache: the forwarder with its cache against the real resolvers
// (NUXK_DNS_LIVE=1, through NUXK_DNS_LIVE_IFACE if set): asked again — from
// the cache, quicker, TTL counted down; the way out gone and the answers
// expired — the old ones stand in within staleWait.
func TestLiveCache(t *testing.T) {
	if os.Getenv("NUXK_DNS_LIVE") == "" {
		t.Skip("NUXK_DNS_LIVE not set")
	}
	iface := os.Getenv("NUXK_DNS_LIVE_IFACE")
	clk := &clock{t: time.Now()}
	var down atomic.Bool
	s := New(Options{Listen: freeAddr(t), Clock: clk.Now, Paths: func() []Path {
		if iface == "" {
			return nil
		}
		return []Path{{Name: "warp", Iface: iface}}
	}}, nil)
	s.o.Transport = func(p Path) http.RoundTripper {
		rt := s.transport(p)
		return rtFunc(func(r *http.Request) (*http.Response, error) {
			if down.Load() {
				return nil, errors.New("outage")
			}
			return rt.RoundTrip(r)
		})
	}
	if err := s.start(); err != nil {
		t.Fatal(err)
	}
	defer s.stop()
	names := []string{"cloudflare.com", "github.com", "www.youtube.com", "chatgpt.com", "rutor.info", "nxdomain-nuxk-check.example.com"}
	for _, name := range names {
		t0 := time.Now()
		first := ask(t, "udp", s.o.Listen, name)
		miss := time.Since(t0)
		clk.Add(2 * time.Second)
		t0 = time.Now()
		again := ask(t, "udp", s.o.Listen, name)
		hit := time.Since(t0)
		a1, _ := Parse(first)
		a2, _ := Parse(again)
		t1, _ := ttlIn(first)
		t2, _ := ttlIn(again)
		t.Logf("%-32s rcode %d %v ttl %d→%d  miss %v hit %v", name, a1.Rcode, a1.Addrs, t1, t2,
			miss.Round(time.Millisecond), hit.Round(100*time.Microsecond))
		if a1.Rcode != a2.Rcode || len(a1.Addrs) != len(a2.Addrs) || (t1 > 2 && t2 > t1-2) {
			t.Errorf("%s: the cache's answer differs: %+v / %+v, ttl %d→%d", name, a1, a2, t1, t2)
		}
	}
	st := s.Status()
	t.Logf("cache: %+v, last path %s", st.Cache, st.LastPath)

	down.Store(true)
	clk.Add(2 * time.Hour)
	for _, name := range names[:5] {
		t0 := time.Now()
		resp := ask(t, "udp", s.o.Listen, name)
		a, _ := Parse(resp)
		ttl, _ := ttlIn(resp)
		t.Logf("outage: %-18s rcode %d %v ttl %d in %v", name, a.Rcode, a.Addrs, ttl, time.Since(t0).Round(time.Millisecond))
		if a.Rcode != RcodeNoError || len(a.Addrs) == 0 || ttl != staleTTL || time.Since(t0) > 3*time.Second {
			t.Errorf("outage: %s: no stale answer", name)
		}
	}
	down.Store(false)
	if a, err := Parse(ask(t, "udp", s.o.Listen, "cloudflare.com")); err != nil || len(a.Addrs) == 0 {
		t.Errorf("after the outage: %v %+v", err, a)
	}
	t.Logf("cache: %+v", s.Status().Cache)
}
