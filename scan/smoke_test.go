package scan

import (
	"testing"

	"github.com/miekg/dns"
)

// TestResolverSmoke exercises live DNS queries; skipped under -short.
func TestResolverSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	r := NewResolver("")
	got := map[string][]string{}
	for rs := range r.AllRecords("example.com") {
		if rs.Err != nil {
			t.Logf("%-6s ERR %v", rs.Type, rs.Err)
			continue
		}
		got[rs.Type] = rs.Records
	}
	if len(got["A"]) == 0 && len(got["AAAA"]) == 0 {
		t.Errorf("expected A/AAAA records for example.com, got none")
	}
	if len(got["NS"]) == 0 {
		t.Errorf("expected NS records for example.com, got none")
	}
}

// TestSubdomainSmoke exercises live subdomain enumeration; skipped under -short.
func TestSubdomainSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	r := NewResolver("")
	found, certs, prog := r.EnumerateSubdomains("github.com", true)
	done := make(chan struct{}, 2)
	go func() {
		for range prog {
		}
		done <- struct{}{}
	}()
	var harvested int
	go func() {
		for range certs {
			harvested++
		}
		done <- struct{}{}
	}()
	var subs []Subdomain
	for s := range found {
		subs = append(subs, s)
	}
	<-done
	<-done
	if len(subs) == 0 {
		t.Error("expected to discover subdomains for github.com, found none")
	}
	t.Logf("found %d subdomains, %d certificates", len(subs), harvested)
}

// TestTruncatedAnswerSmoke guards the EDNS0 + TCP fallback path: these
// domains publish TXT sets far larger than the 512-byte UDP default, and
// without the fallback they come back empty rather than truncated.
func TestTruncatedAnswerSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	r := NewResolver("")
	for _, domain := range []string{"google.com", "microsoft.com"} {
		recs, err := r.Query(domain, dns.TypeTXT)
		if err != nil {
			t.Errorf("%s TXT: %v", domain, err)
			continue
		}
		if len(recs) < 5 {
			t.Errorf("%s TXT: got %d records, expected a large set (truncation not handled?)", domain, len(recs))
		}
	}
}
