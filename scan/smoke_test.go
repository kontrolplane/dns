package scan

import "testing"

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
	found, prog := r.EnumerateSubdomains("github.com", true)
	done := make(chan struct{})
	go func() {
		for range prog {
		}
		close(done)
	}()
	var subs []Subdomain
	for s := range found {
		subs = append(subs, s)
	}
	<-done
	if len(subs) == 0 {
		t.Error("expected to discover subdomains for github.com, found none")
	}
}
