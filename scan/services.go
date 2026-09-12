package scan

import "github.com/miekg/dns"

// ServiceRecord is an answer found at one of the well-known service names.
type ServiceRecord struct {
	Name    string // the probed label, e.g. "_dmarc"
	Type    string
	Records []string
}

// serviceProbes are fixed names that carry high-signal records but that no
// hostname wordlist reaches, because they are service labels rather than
// hosts. They describe a domain's mail authentication, certificate issuance
// and client autoconfiguration, and they frequently name the third parties
// behind all three — a DKIM selector pointing at a tenant, or an ACME
// challenge delegated to an entirely different domain.
var serviceProbes = []struct {
	name  string
	types []uint16
}{
	// Mail authentication and reporting.
	{"_dmarc", []uint16{dns.TypeTXT}},
	{"_mta-sts", []uint16{dns.TypeTXT}},
	{"_smtp._tls", []uint16{dns.TypeTXT}},
	{"_domainkey", []uint16{dns.TypeTXT}},
	{"default._domainkey", []uint16{dns.TypeTXT, dns.TypeCNAME}},
	{"google._domainkey", []uint16{dns.TypeTXT, dns.TypeCNAME}},
	{"selector1._domainkey", []uint16{dns.TypeTXT, dns.TypeCNAME}},
	{"selector2._domainkey", []uint16{dns.TypeTXT, dns.TypeCNAME}},
	{"s1._domainkey", []uint16{dns.TypeTXT, dns.TypeCNAME}},
	{"s2._domainkey", []uint16{dns.TypeTXT, dns.TypeCNAME}},
	{"k1._domainkey", []uint16{dns.TypeTXT, dns.TypeCNAME}},
	{"mail._domainkey", []uint16{dns.TypeTXT, dns.TypeCNAME}},
	{"dkim._domainkey", []uint16{dns.TypeTXT, dns.TypeCNAME}},
	{"protonmail._domainkey", []uint16{dns.TypeTXT, dns.TypeCNAME}},
	{"zmail._domainkey", []uint16{dns.TypeTXT, dns.TypeCNAME}},

	// Certificate issuance.
	{"_acme-challenge", []uint16{dns.TypeTXT, dns.TypeCNAME}},

	// Transport security bound to a port.
	{"_443._tcp", []uint16{dns.TypeTLSA}},
	{"_25._tcp", []uint16{dns.TypeTLSA}},

	// Client autoconfiguration and directory services.
	{"_autodiscover._tcp", []uint16{dns.TypeSRV}},
	{"_autodiscover._tcp.autodiscover", []uint16{dns.TypeSRV}},
	{"_sipfederationtls._tcp", []uint16{dns.TypeSRV}},
	{"_caldav._tcp", []uint16{dns.TypeSRV}},
	{"_caldavs._tcp", []uint16{dns.TypeSRV}},
	{"_carddav._tcp", []uint16{dns.TypeSRV}},
	{"_carddavs._tcp", []uint16{dns.TypeSRV}},
	{"_ldap._tcp", []uint16{dns.TypeSRV}},
	{"_kerberos._tcp", []uint16{dns.TypeSRV}},
	{"_kerberos._udp", []uint16{dns.TypeSRV}},
	{"_kpasswd._tcp", []uint16{dns.TypeSRV}},

	// Messaging and voice.
	{"_sip._tcp", []uint16{dns.TypeSRV}},
	{"_sip._udp", []uint16{dns.TypeSRV}},
	{"_sips._tcp", []uint16{dns.TypeSRV}},
	{"_xmpp-client._tcp", []uint16{dns.TypeSRV}},
	{"_xmpp-server._tcp", []uint16{dns.TypeSRV}},
	{"_matrix._tcp", []uint16{dns.TypeSRV}},
	{"_stun._udp", []uint16{dns.TypeSRV}},

	// Mail transport.
	{"_imap._tcp", []uint16{dns.TypeSRV}},
	{"_imaps._tcp", []uint16{dns.TypeSRV}},
	{"_pop3._tcp", []uint16{dns.TypeSRV}},
	{"_submission._tcp", []uint16{dns.TypeSRV}},
}

// ServiceProbeSize reports how many names the service pass queries.
func ServiceProbeSize() int { return len(serviceProbes) }

// ProbeServices queries the well-known service names beneath domain and emits
// only those that answer. Every probe runs concurrently, so the whole pass
// costs about one round trip.
func (r *Resolver) ProbeServices(domain string) <-chan ServiceRecord {
	ch := make(chan ServiceRecord)
	go func() {
		defer close(ch)
		p := newPool(dnsWorkers)
		for _, probe := range serviceProbes {
			for _, qt := range probe.types {
				p.run(func() {
					recs, err := r.Query(probe.name+"."+domain, qt)
					if err != nil || len(recs) == 0 {
						return
					}
					ch <- ServiceRecord{Name: probe.name, Type: dns.TypeToString[qt], Records: recs}
				})
			}
		}
		p.wait()
	}()
	return ch
}
