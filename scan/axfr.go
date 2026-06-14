package scan

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// axfrSubdomains attempts a zone transfer (AXFR) against each authoritative
// nameserver for domain and returns the candidate label prefixes (the
// portion left of ".<domain>") for every name in the zone, deduplicated.
//
// This is entirely self-contained — it talks DNS directly to the zone's
// nameservers, with no external service. Transfers are almost always refused
// in practice; any failure simply yields no names for that server, so AXFR
// is a best-effort supplement to the wordlist that pays off completely on the
// occasional misconfigured zone.
func (r *Resolver) axfrSubdomains(domain string) []string {
	suffix := "." + domain
	seen := map[string]bool{}
	var words []string

	for _, ns := range r.nameservers(domain) {
		t := &dns.Transfer{DialTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second}
		m := new(dns.Msg)
		m.SetAxfr(dns.Fqdn(domain))

		env, err := t.In(m, net.JoinHostPort(ns, "53"))
		if err != nil {
			continue
		}
		for e := range env {
			if e.Error != nil {
				continue // refused / truncated mid-stream
			}
			for _, rr := range e.RR {
				name := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
				if name == domain || !strings.HasSuffix(name, suffix) {
					continue
				}
				word := strings.TrimSuffix(name, suffix)
				if word == "" || seen[word] {
					continue
				}
				seen[word] = true
				words = append(words, word)
			}
		}
	}
	return words
}

// nameservers returns the authoritative nameserver hostnames for domain
// (trailing dot stripped), or nil if the NS lookup fails.
func (r *Resolver) nameservers(domain string) []string {
	recs, err := r.Query(domain, dns.TypeNS)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(recs))
	for _, rec := range recs {
		if ns := strings.TrimSuffix(strings.TrimSpace(rec), "."); ns != "" {
			out = append(out, ns)
		}
	}
	return out
}
