package api

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"nuxk.dev/horizon/core/internal/core"
	"nuxk.dev/horizon/core/internal/dns"
	"nuxk.dev/horizon/core/internal/engine"
	"nuxk.dev/horizon/core/internal/logbuf"
	"nuxk.dev/horizon/core/internal/node"
	"nuxk.dev/horizon/core/internal/plane"
	"nuxk.dev/horizon/core/internal/update"
)

func readSpec(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The spec lists exactly the endpoints the agent serves — no more (planned
// endpoints stay out until they exist), no less (every route is documented).
func TestOpenAPIMatchesRoutes(t *testing.T) {
	spec := readSpec(t)
	pathRe := regexp.MustCompile(`^  (/api/v1/\S+):\s*$`)
	methRe := regexp.MustCompile(`^    (get|put|post|delete|patch):\s*$`)
	var inSpec []string
	cur := ""
	for _, l := range strings.Split(spec, "\n") {
		if m := pathRe.FindStringSubmatch(l); m != nil {
			cur = m[1]
			continue
		}
		if strings.HasPrefix(l, "components:") {
			break
		}
		if m := methRe.FindStringSubmatch(l); m != nil && cur != "" {
			inSpec = append(inSpec, strings.ToUpper(m[1])+" "+cur)
		}
	}
	var served []string
	for _, r := range Routes {
		served = append(served, r.Pattern)
	}
	sort.Strings(inSpec)
	sort.Strings(served)
	if !reflect.DeepEqual(inSpec, served) {
		t.Fatalf("openapi.yaml and api.Routes differ:\n spec:   %v\n served: %v", inSpec, served)
	}
}

// Every JSON field the agent sends is described in its schema.
func TestOpenAPISchemasCoverJSONFields(t *testing.T) {
	spec := readSpec(t)
	for schema, v := range map[string]any{
		"Credentials":    credentials{},
		"SessionInfo":    SessionInfo{},
		"PairInfo":       PairInfo{},
		"NodeInfo":       node.Info{},
		"Metrics":        node.Metrics{},
		"IfaceCounters":  node.Iface{},
		"NFQueue":        node.Queue{},
		"LogEntry":       logbuf.Entry{},
		"EngineInfo":     engine.Info{},
		"Probe":          engine.Probe{},
		"ProbeCheck":     engine.ProbeCheck{},
		"ProbeSites":     core.ProbeSites{},
		"Upstream":       engine.Upstream{},
		"UpstreamServer": engine.UpstreamServer{},
		"UpstreamUsage":  engine.UpstreamUsage{},
		"Routing":        engine.Routing{},
		"Strategy":       engine.Strategy{},
		"StrategySet":    StrategySet{},
		"PlaneStatus":    plane.Status{},
		"PlaneDesired":   plane.Desired{},
		"PlaneList":      plane.List{},
		"PlaneGroup":     plane.Group{},
		"PlaneOp":        plane.Op{},
		"PlaneConflict":  plane.Conflict{},
		"PlaneForeign":   plane.Foreign{},
		"Status":         core.Snapshot{},
		"UpdateSettings": update.Settings{},
		"UpdateRelease":  update.Release{},
		"UpdateRun":      update.Run{},
		"UpdateStatus":   update.Status{},
		"DNSSettings":    dns.Settings{},
		"DNSResolver":    dns.Resolver{},
		"DNSPathStat":    dns.PathStat{},
		"DNSStatus":      dns.Status{},
		"DNSCheckItem":   dns.CheckItem{},
		"DNSCheck":       dns.Check{},
		"DNSCache":       dns.CacheStat{},
	} {
		block := schemaBlock(t, spec, schema)
		typ := reflect.TypeOf(v)
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			if !strings.Contains(block, "\n        "+name+":") {
				t.Errorf("schema %s lacks field %q (Go %s.%s)", schema, name, typ.Name(), f.Name)
			}
		}
	}
}

func schemaBlock(t *testing.T, spec, name string) string {
	t.Helper()
	i := strings.Index(spec, "\n    "+name+":\n")
	if i < 0 {
		t.Fatalf("schema %s missing", name)
	}
	rest := spec[i+1:]
	next := regexp.MustCompile(`\n    [A-Za-z]+:`).FindStringIndex(rest[1:])
	if next == nil {
		return rest
	}
	return rest[:next[0]+1]
}
