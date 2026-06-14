package scan

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// RecordSet holds the answers for a single DNS record type.
type RecordSet struct {
	Type    string
	Records []string
	Err     error
}

// recordTypes is the set of record types queried for the apex domain.
var recordTypes = []struct {
	name string
	t    uint16
}{
	{"A", dns.TypeA},
	{"AAAA", dns.TypeAAAA},
	{"CNAME", dns.TypeCNAME},
	{"MX", dns.TypeMX},
	{"NS", dns.TypeNS},
	{"TXT", dns.TypeTXT},
	{"SOA", dns.TypeSOA},
	{"SRV", dns.TypeSRV},
	{"CAA", dns.TypeCAA},
	{"PTR", dns.TypePTR},
}

// Resolver wraps a DNS client and the upstream server to query.
type Resolver struct {
	client *dns.Client
	server string
}

// NewResolver builds a resolver. When server is non-empty it is used as the
// upstream nameserver (a bare address is given the default port 53);
// otherwise the system's configured nameserver is preferred, falling back to
// Cloudflare's 1.1.1.1.
func NewResolver(server string) *Resolver {
	switch {
	case server != "":
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(server, "53")
		}
	default:
		server = "1.1.1.1:53"
		if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
			server = cfg.Servers[0] + ":" + cfg.Port
		}
	}
	return &Resolver{
		client: &dns.Client{Timeout: 5 * time.Second},
		server: server,
	}
}

// Server reports the upstream nameserver in use.
func (r *Resolver) Server() string { return r.server }

// Query looks up a single record type and returns formatted answers.
func (r *Resolver) Query(domain string, qtype uint16) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	resp, _, err := r.client.Exchange(m, r.server)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("server returned %s", dns.RcodeToString[resp.Rcode])
	}

	var out []string
	for _, rr := range resp.Answer {
		out = append(out, formatRR(rr))
	}
	sort.Strings(out)
	return out, nil
}

// AllRecords queries every record type for the domain, emitting each
// result onto the returned channel as it completes.
func (r *Resolver) AllRecords(domain string) <-chan RecordSet {
	ch := make(chan RecordSet)
	go func() {
		defer close(ch)
		for _, rt := range recordTypes {
			recs, err := r.Query(domain, rt.t)
			ch <- RecordSet{Type: rt.name, Records: recs, Err: err}
		}
	}()
	return ch
}

// formatRR renders a resource record as a readable one-liner, stripping
// the redundant owner/class/ttl header that dns.RR.String() prepends.
func formatRR(rr dns.RR) string {
	header := rr.Header().String()
	full := rr.String()
	return strings.TrimSpace(strings.TrimPrefix(full, header))
}
