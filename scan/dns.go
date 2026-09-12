package scan

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Query tuning. The timeout is short because a lost UDP datagram is retried
// rather than waited out: a retry recovers the answer in a fraction of the
// time a long timeout costs, and an unanswered query is indistinguishable
// from a name that does not exist, so dropping one silently loses a record.
const (
	queryTimeout  = 2 * time.Second
	queryAttempts = 2
	retryBackoff  = 50 * time.Millisecond

	// udpBufSize is the EDNS0 buffer advertised to the server. Without it the
	// server is held to the 512-byte default and anything larger comes back
	// truncated and empty — which is most real domains' TXT sets.
	udpBufSize = 4096
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
	udp    *dns.Client
	tcp    *dns.Client
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
		udp:    &dns.Client{Timeout: queryTimeout},
		tcp:    &dns.Client{Net: "tcp", Timeout: queryTimeout},
		server: server,
	}
}

// Server reports the upstream nameserver in use.
func (r *Resolver) Server() string { return r.server }

// question builds a recursive query for domain, advertising an EDNS0 buffer
// so large answers arrive whole.
func question(domain string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true
	m.SetEdns0(udpBufSize, false)
	return m
}

// exchange sends m upstream, retrying a lost datagram or a transient server
// failure, and re-asking over TCP when the answer is too large for UDP.
func (r *Resolver) exchange(m *dns.Msg) (*dns.Msg, error) {
	var err error
	for attempt := 0; attempt < queryAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(retryBackoff)
		}

		var resp *dns.Msg
		resp, _, err = r.udp.Exchange(m, r.server)
		if err != nil {
			continue // timeout or lost datagram — worth asking again
		}

		switch resp.Rcode {
		case dns.RcodeFormatError, dns.RcodeNotImplemented:
			// A server too old to understand EDNS0. Drop the OPT record and
			// accept the 512-byte limit rather than returning nothing.
			plain := m.Copy()
			plain.Extra = nil
			if bare, _, bareErr := r.udp.Exchange(plain, r.server); bareErr == nil {
				resp = bare
			}
		case dns.RcodeServerFailure, dns.RcodeRefused:
			err = fmt.Errorf("server returned %s", dns.RcodeToString[resp.Rcode])
			continue
		}

		if resp.Truncated {
			// The answer did not fit the advertised buffer. TCP has no such
			// limit; a failure here leaves the truncated answer in place.
			if full, _, tcpErr := r.tcp.Exchange(m, r.server); tcpErr == nil {
				resp = full
			}
		}
		return resp, nil
	}
	return nil, err
}

// Query looks up a single record type and returns formatted answers.
func (r *Resolver) Query(domain string, qtype uint16) ([]string, error) {
	resp, err := r.exchange(question(domain, qtype))
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
