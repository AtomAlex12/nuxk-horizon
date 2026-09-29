package dns

import (
	"container/list"
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

// The cache: answers kept for as long as their records allow (RFC 1035 TTLs,
// RFC 2308 for «no such name»), handed back with the time left.
//
// The router's DNS proxy caches too, so this is less about speed than about
// keeping the network going: names people use are refreshed ahead of expiry,
// and when no way out answers in time an expired answer is handed back with a
// short TTL (serve-stale, RFC 8767) — sites opened before keep opening while a
// tunnel reconnects. Memory is bounded: a MIPS router has little.

const (
	cacheMaxEntries = 5000
	cacheMaxBytes   = 2 << 20
	cacheMaxMsg     = 8 << 10 // bigger answers aren't kept

	maxTTL      = 24 * 60 * 60 // a day, whatever the zone says
	maxNegTTL   = 5 * 60       // «no such name»: five minutes at most
	staleTTL    = 30           // an expired answer is handed out for 30 s (RFC 8767)
	staleMax    = 24 * time.Hour
	staleWait   = 1800 * time.Millisecond // then an expired answer beats waiting
	refreshMin  = 30                      // records living less aren't refreshed ahead
	refreshLead = 10                      // …and the rest this close to expiry (or a tenth of their TTL)

	typeSOA  = 6
	typeIXFR = 251
	typeAXFR = 252
	typeANY  = 255
)

// CacheStat: how the cache has been doing (Status.Cache).
type CacheStat struct {
	Entries   int    `json:"entries"`
	Bytes     int    `json:"bytes"`
	Hits      uint64 `json:"hits"`      // answered from the cache
	Misses    uint64 `json:"misses"`    // not there (or expired): asked the resolvers
	Stale     uint64 `json:"stale"`     // an expired answer handed back: no way out answered in time
	Refreshed uint64 `json:"refreshed"` // names in use refreshed ahead of expiry
}

type entry struct {
	key    string
	query  []byte   // asked again to refresh it
	msg    []byte   // the answer, ID 0
	qend   int      // the end of its question
	ttls   []int    // offsets of the TTL fields (OPT's is flags, not a TTL)
	orig   []uint32 // the TTLs as they came
	ttl    uint32   // how long it's fresh
	stored time.Time
	asks   int       // times asked for (kept when refreshed): a name in use
	asked  time.Time // last asked
	size   int
}

func (e *entry) expires() time.Time { return e.stored.Add(time.Duration(e.ttl) * time.Second) }

// reply: the answer for q — its ID, its spelling of the name (0x20), the TTLs
// counted down; an expired one goes out with staleTTL.
func (e *entry) reply(q []byte, now time.Time, stale bool) []byte {
	m := own(e.msg, q)
	age := uint32(max(now.Sub(e.stored), 0) / time.Second)
	for i, off := range e.ttls {
		t := uint32(staleTTL)
		if !stale {
			t = 0
			if e.orig[i] > age {
				t = e.orig[i] - age
			}
		}
		binary.BigEndian.PutUint32(m[off:off+4], t)
	}
	return m
}

// own: resp as the answer to q — q's ID and q's spelling of the name.
func own(resp, q []byte) []byte {
	m := append([]byte(nil), resp...)
	m[0], m[1] = q[0], q[1]
	if qe, err := questionEnd(q); err == nil {
		if re, err := questionEnd(m); err == nil && re == qe {
			copy(m[headerLen:qe], q[headerLen:qe])
		}
	}
	return m
}

type cache struct {
	mu    sync.Mutex
	ll    *list.List // front: used last
	items map[string]*list.Element
	bytes int
	stat  CacheStat
}

func newCache() *cache {
	return &cache{ll: list.New(), items: map[string]*list.Element{}}
}

// cacheKey: what makes two questions the same — the name in any case, type,
// class, and the flags that change the answer (RD, CD, EDNS, DO). "" for
// what isn't kept: not a plain query, several questions, zone transfers, ANY.
func cacheKey(q []byte) string {
	if len(q) < headerLen || q[2]&0x80 != 0 || q[2]&0x78 != 0 {
		return ""
	}
	if binary.BigEndian.Uint16(q[4:6]) != 1 || binary.BigEndian.Uint16(q[6:8]) != 0 || binary.BigEndian.Uint16(q[8:10]) != 0 {
		return ""
	}
	end, err := questionEnd(q)
	if err != nil {
		return ""
	}
	// the name has no pointers in a query we take: labels only
	for off := headerLen; off < end-4; {
		l := int(q[off])
		if l == 0 {
			break
		}
		if l&0xC0 != 0 {
			return ""
		}
		off += 1 + l
	}
	switch binary.BigEndian.Uint16(q[end-4 : end-2]) {
	case typeIXFR, typeAXFR, typeANY:
		return ""
	}
	var flags byte
	if q[2]&0x01 != 0 {
		flags |= 1 // RD
	}
	if q[3]&0x10 != 0 {
		flags |= 2 // CD
	}
	off := end
	for n := int(binary.BigEndian.Uint16(q[10:12])); n > 0; n-- {
		if off, err = skipName(q, off); err != nil || off+10 > len(q) {
			return ""
		}
		if binary.BigEndian.Uint16(q[off:off+2]) != typeOPT {
			return "" // only EDNS rides along with a plain query
		}
		flags |= 4 // EDNS
		if q[off+6]&0x80 != 0 {
			flags |= 8 // DO
		}
		off += 10 + int(binary.BigEndian.Uint16(q[off+8:off+10]))
	}
	return strings.ToLower(string(q[headerLen:end])) + string([]byte{flags})
}

// parseEntry: resp as a cache entry for q, or nil when it isn't to be kept —
// an error, a truncated answer, a question that isn't q's, a zero TTL, «no
// such name» without the zone's SOA to say for how long.
func parseEntry(key string, q, resp []byte) *entry {
	if len(resp) < headerLen || len(resp) > cacheMaxMsg || resp[2]&0x80 == 0 || resp[2]&0x7A != 0 {
		return nil // not a response, not a plain query's, truncated
	}
	rcode := resp[3] & 0x0F
	if rcode != RcodeNoError && rcode != RcodeNXDomain {
		return nil
	}
	qend, err := questionEnd(q)
	if err != nil || binary.BigEndian.Uint16(resp[4:6]) != 1 {
		return nil
	}
	if e, err := questionEnd(resp); err != nil || e != qend || !strings.EqualFold(string(resp[headerLen:qend]), string(q[headerLen:qend])) {
		return nil
	}
	e := &entry{key: key, query: append([]byte(nil), q...), msg: append([]byte(nil), resp...), qend: qend}
	e.msg[0], e.msg[1] = 0, 0
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	ns := int(binary.BigEndian.Uint16(resp[8:10]))
	ar := int(binary.BigEndian.Uint16(resp[10:12]))
	var minTTL, negTTL uint32 = maxTTL, 0
	haveSOA := false
	off := qend
	for i := 0; i < an+ns+ar; i++ {
		if off, err = skipName(resp, off); err != nil || off+10 > len(resp) {
			return nil
		}
		typ := binary.BigEndian.Uint16(resp[off : off+2])
		ttl := binary.BigEndian.Uint32(resp[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(resp[off+8 : off+10]))
		if off+10+rdlen > len(resp) {
			return nil
		}
		if typ != typeOPT {
			ttl = min(ttl, maxTTL)
			e.ttls = append(e.ttls, off+4)
			e.orig = append(e.orig, ttl)
			if i < an+ns {
				minTTL = min(minTTL, ttl)
			}
			if typ == typeSOA && i >= an && i < an+ns && rdlen >= 20 {
				soaMin := binary.BigEndian.Uint32(resp[off+10+rdlen-4 : off+10+rdlen])
				negTTL, haveSOA = min(ttl, soaMin), true
			}
		}
		off += 10 + rdlen
	}
	switch {
	case rcode == RcodeNoError && an > 0:
		e.ttl = minTTL
	case haveSOA: // «no such name», or the name without this type
		e.ttl = min(negTTL, maxNegTTL)
	default:
		return nil
	}
	if e.ttl == 0 {
		return nil
	}
	e.size = len(e.query) + len(e.msg) + len(key) + 12*len(e.ttls) + 160
	return e
}

// get: the entry for key, fresh or not, and whether it's still fresh; one
// expired longer than staleMax is dropped.
func (c *cache) get(key string, now time.Time) (*entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el := c.items[key]
	if el == nil {
		return nil, false
	}
	e := el.Value.(*entry)
	if now.After(e.expires().Add(staleMax)) {
		c.remove(el)
		return nil, false
	}
	c.ll.MoveToFront(el)
	e.asks++
	e.asked = now
	return e, now.Before(e.expires())
}

// put keeps e (a name in use stays one when refreshed) and evicts the least
// recently used past the limits.
func (c *cache) put(e *entry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.stored = now
	if el := c.items[e.key]; el != nil {
		old := el.Value.(*entry)
		e.asks, e.asked = old.asks, old.asked
		c.remove(el)
	} else {
		e.asks, e.asked = 1, now // asked for once: that's why it's here
	}
	c.items[e.key] = c.ll.PushFront(e)
	c.bytes += e.size
	for c.ll.Len() > 0 && (c.ll.Len() > cacheMaxEntries || c.bytes > cacheMaxBytes) {
		c.remove(c.ll.Back())
	}
}

func (c *cache) remove(el *list.Element) {
	e := el.Value.(*entry)
	c.ll.Remove(el)
	delete(c.items, e.key)
	c.bytes -= e.size
}

// due: names in use about to expire — to be refreshed ahead (at most n);
// entries expired past staleMax go.
func (c *cache) due(now time.Time, n int) []*entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*entry
	for el := c.ll.Back(); el != nil; {
		prev := el.Prev()
		e := el.Value.(*entry)
		exp := e.expires()
		switch {
		case now.After(exp.Add(staleMax)):
			c.remove(el)
		case len(out) < n && e.asks >= 2 && e.ttl >= refreshMin && now.Before(exp) &&
			exp.Sub(now) <= max(time.Duration(e.ttl/10), refreshLead)*time.Second &&
			now.Sub(e.asked) <= max(3*time.Duration(e.ttl)*time.Second, 10*time.Minute):
			out = append(out, e)
		}
		el = prev
	}
	return out
}

func (c *cache) flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.items = map[string]*list.Element{}
	c.bytes = 0
}

func (c *cache) count(f func(*CacheStat)) {
	c.mu.Lock()
	f(&c.stat)
	c.mu.Unlock()
}

func (c *cache) stats() CacheStat {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.stat
	st.Entries, st.Bytes = c.ll.Len(), c.bytes
	return st
}
