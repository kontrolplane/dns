package scan

import (
	"sync"
	"testing"
)

// These run without a network so they execute under -short in CI.

func TestWildcardSynthesised(t *testing.T) {
	none := wildcard{addrs: map[string]bool{}}
	if none.synthesised([]string{"1.2.3.4"}) {
		t.Error("a zone with no wildcard should reject nothing")
	}

	wc := wildcard{addrs: map[string]bool{"1.2.3.4": true, "5.6.7.8": true}}
	for _, tc := range []struct {
		name string
		recs []string
		want bool
	}{
		{"exactly the wildcard answer", []string{"1.2.3.4", "5.6.7.8"}, true},
		{"a subset of it", []string{"1.2.3.4"}, true},
		{"one address the wildcard never returns", []string{"1.2.3.4", "9.9.9.9"}, false},
		{"an unrelated address", []string{"9.9.9.9"}, false},
	} {
		if got := wc.synthesised(tc.recs); got != tc.want {
			t.Errorf("%s: synthesised(%v) = %v, want %v", tc.name, tc.recs, got, tc.want)
		}
	}
}

func TestCertCandidates(t *testing.T) {
	got := certCandidates([]string{
		"example.com",           // the apex itself
		"api.example.com",       // in scope
		"a.b.example.com",       // nested, in scope
		"*.example.com",         // wildcard, nothing concrete to probe
		"API.Example.com",       // case-folded duplicate of api
		"example.com.evil.test", // suffix lookalike, out of scope
		"other.org",             // out of scope
	}, "example.com")

	want := map[string]int{"api": 2, "a.b": 1}
	counts := map[string]int{}
	for _, w := range got {
		counts[w]++
	}
	for w, n := range want {
		if counts[w] != n {
			t.Errorf("candidate %q: got %d, want %d (all: %v)", w, counts[w], n, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("got %d candidates %v, want exactly 3", len(got), got)
	}
}

func TestWordlistLoads(t *testing.T) {
	words := wordlist()
	if len(words) < 100 {
		t.Fatalf("wordlist has %d entries, expected the embedded list", len(words))
	}
	if len(words) != WordlistSize() {
		t.Errorf("WordlistSize reports %d, wordlist has %d", WordlistSize(), len(words))
	}
	for _, w := range words {
		if w == "" || w[0] == '#' {
			t.Errorf("wordlist contains a blank or comment entry: %q", w)
		}
	}
}

func TestRecordTypesMatchTable(t *testing.T) {
	names := RecordTypes()
	if len(names) != len(recordTypes) {
		t.Fatalf("RecordTypes returned %d names for %d types", len(names), len(recordTypes))
	}
	for i, rt := range recordTypes {
		if names[i] != rt.name {
			t.Errorf("position %d: RecordTypes gave %q, table has %q", i, names[i], rt.name)
		}
	}
}

// The pool must bound live goroutines rather than the work list, which is what
// keeps a large zone transfer from costing a goroutine per name.
func TestPoolBoundsConcurrency(t *testing.T) {
	const (
		limit = 4
		jobs  = 500
	)
	var (
		mu       sync.Mutex
		live     int
		peak     int
		finished int
	)
	p := newPool(limit)
	for i := 0; i < jobs; i++ {
		p.run(func() {
			mu.Lock()
			live++
			if live > peak {
				peak = live
			}
			mu.Unlock()

			mu.Lock()
			live--
			finished++
			mu.Unlock()
		})
	}
	p.wait()

	if finished != jobs {
		t.Errorf("ran %d jobs, expected %d", finished, jobs)
	}
	if peak > limit {
		t.Errorf("peak concurrency %d exceeded the pool limit %d", peak, limit)
	}
}

func TestRandomLabelIsUnlikely(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		l := randomLabel()
		if len(l) != 16 {
			t.Fatalf("label %q has length %d, want 16", l, len(l))
		}
		if seen[l] {
			t.Fatalf("label %q repeated within 100 draws", l)
		}
		seen[l] = true
	}
}
