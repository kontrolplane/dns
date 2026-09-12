package scan

import (
	_ "embed"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

//go:embed wordlist.txt
var wordlistRaw string

// Pool sizes for the two passes. They are separate so that a TLS handshake,
// which can take seconds, never occupies capacity the resolver needs. The DNS
// side is only a work queue — the real limit on queries in flight is
// maxInflight, enforced by the resolver itself, so that concurrent passes
// cannot add up to more than it.
const (
	dnsWorkers  = maxInflight
	certWorkers = 32
)

// Subdomain is a discovered hostname and the addresses it resolves to.
// Certificates arrive separately, on their own channel, because they are
// fetched after the name is already known and worth showing.
type Subdomain struct {
	Name string
	IPs  []string
}

// CertResult is a leaf TLS certificate harvested from a discovered host.
type CertResult struct {
	Host string
	Info *CertInfo
}

// wordlist returns the embedded subdomain candidates.
func wordlist() []string {
	var words []string
	for _, line := range strings.Split(wordlistRaw, "\n") {
		if w := strings.TrimSpace(line); w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}
	return words
}

// WordlistSize reports the static wordlist length, used as the initial
// progress denominator before discovered names are merged in.
func WordlistSize() int { return len(wordlist()) }

// EnumerateSubdomains probes candidate subdomains against the domain and
// emits each one that exists on found, its certificate on certs, and a
// Progress tick per candidate tried.
//
// Candidates come from three sources: the embedded wordlist, a zone-transfer
// (AXFR) attempt, and — the in-app form of certificate-transparency discovery
// — the Subject Alternative Names read off each live host's own certificate.
// Because that last source feeds new candidates back in, work runs in rounds:
// every candidate in a round is resolved, then the certificates of whatever
// turned up are read, and any novel SANs become the next round. Rounds after
// the first are small, and the structure keeps the queue an ordinary slice
// however large a zone transfer turns out to be.
//
// Certificate harvesting (and the SAN feedback it drives) happens only when
// harvest is true.
func (r *Resolver) EnumerateSubdomains(domain string, harvest bool) (found <-chan Subdomain, certs <-chan CertResult, progress <-chan int) {
	foundCh := make(chan Subdomain)
	certCh := make(chan CertResult)
	progCh := make(chan int)

	go func() {
		defer close(foundCh)
		defer close(certCh)
		defer close(progCh)

		seen := map[string]bool{"": true}
		var queued []string
		admit := func(words []string) {
			for _, w := range words {
				if !seen[w] {
					seen[w] = true
					queued = append(queued, w)
				}
			}
		}

		admit(wordlist())
		admit(r.axfrSubdomains(domain))

		// The apex's own certificate is usually the richest SAN source, so
		// read it up front rather than waiting for a round to reach it.
		if harvest {
			if leaf := r.fetchCert(domain); leaf != nil {
				certCh <- CertResult{Host: domain, Info: certInfo(leaf)}
				admit(certCandidates(leaf.DNSNames, domain))
			}
		}

		total := 0
		for len(queued) > 0 {
			batch := queued
			queued = nil
			total += len(batch)

			var (
				mu   sync.Mutex
				live []string
			)

			resolvers := newPool(dnsWorkers)
			for _, word := range batch {
				host := word + "." + domain
				resolvers.run(func() {
					if ips, ok := r.lookupHost(host); ok {
						foundCh <- Subdomain{Name: host, IPs: ips}
						mu.Lock()
						live = append(live, host)
						mu.Unlock()
					}
					progCh <- total
				})
			}
			resolvers.wait()

			if !harvest {
				continue
			}

			var sans []string
			handshakes := newPool(certWorkers)
			for _, host := range live {
				handshakes.run(func() {
					leaf := r.fetchCert(host)
					if leaf == nil {
						return
					}
					certCh <- CertResult{Host: host, Info: certInfo(leaf)}
					mu.Lock()
					sans = append(sans, certCandidates(leaf.DNSNames, domain)...)
					mu.Unlock()
				})
			}
			handshakes.wait()
			admit(sans)
		}
	}()

	return foundCh, certCh, progCh
}

// lookupHost resolves a candidate and reports whether it answered. A and AAAA
// are asked concurrently, so a candidate costs one round trip rather than two.
func (r *Resolver) lookupHost(host string) ([]string, bool) {
	var (
		qtypes = [...]uint16{dns.TypeA, dns.TypeAAAA}
		answer [len(qtypes)][]string
		wg     sync.WaitGroup
	)

	for i, qt := range qtypes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := r.exchange(question(host, qt))
			if err != nil {
				return
			}
			for _, rr := range resp.Answer {
				answer[i] = append(answer[i], formatRR(rr))
			}
		}()
	}
	wg.Wait()

	seen := map[string]bool{}
	var ips []string
	for _, recs := range answer {
		for _, rec := range recs {
			if !seen[rec] {
				seen[rec] = true
				ips = append(ips, rec)
			}
		}
	}
	return ips, len(ips) > 0
}
