package scan

import (
	_ "embed"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

//go:embed wordlist.txt
var wordlistRaw string

// Subdomain is a discovered hostname, the addresses it resolves to, and its
// leaf TLS certificate if one could be fetched.
type Subdomain struct {
	Name string
	IPs  []string
	Cert *CertInfo
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

// EnumerateSubdomains probes candidate subdomains against the domain using a
// bounded, self-feeding worker pool. Each resolving host is emitted on found
// (with its TLS certificate if one was presented) and every candidate tried
// emits a Progress tick. Candidates come from three sources: the embedded
// wordlist, a zone-transfer (AXFR) attempt, and — the in-app form of
// certificate-transparency discovery — the Subject Alternative Names read off
// each live host's own certificate, fed back in as new candidates. The total
// reported on each tick grows as those names are admitted. Certificate
// harvesting (and the SAN feedback it drives) happens only when certs is true.
func (r *Resolver) EnumerateSubdomains(domain string, certs bool) (found <-chan Subdomain, progress <-chan int) {
	foundCh := make(chan Subdomain)
	progCh := make(chan int)

	go func() {
		defer close(foundCh)
		defer close(progCh)

		// mu guards seen (dedup across all sources) and total (the progress
		// denominator).
		var mu sync.Mutex
		seen := map[string]bool{}
		total := 0
		curTotal := func() int { mu.Lock(); defer mu.Unlock(); return total }

		const workers = 50
		jobs := make(chan string)
		var wg sync.WaitGroup // counts queued-but-unprocessed candidates

		// submit admits novel candidates and queues them. Safe to call from a
		// worker (the send runs in its own goroutine so it never blocks the
		// pool). wg tracks each item from submit to processed, so the seeding
		// sentinel below keeps the pool alive until all sources have fed in.
		submit := func(words []string) {
			mu.Lock()
			var novel []string
			for _, w := range words {
				if w != "" && !seen[w] {
					seen[w] = true
					novel = append(novel, w)
				}
			}
			total += len(novel)
			mu.Unlock()
			for _, w := range novel {
				wg.Add(1)
				go func(w string) { jobs <- w }(w)
			}
		}

		for i := 0; i < workers; i++ {
			go func() {
				for word := range jobs {
					host := word + "." + domain
					if ips := r.resolveHost(host); len(ips) > 0 {
						sub := Subdomain{Name: host, IPs: ips}
						if certs {
							if leaf := r.fetchCert(host); leaf != nil {
								sub.Cert = certInfo(leaf)
								submit(certCandidates(leaf.DNSNames, domain)) // feed SANs back
							}
						}
						foundCh <- sub
					}
					progCh <- curTotal()
					wg.Done()
				}
			}()
		}

		// Seed the pool. The sentinel keeps wg above zero until every seed
		// source (including the slow AXFR and apex-cert fetches) has been fed,
		// so wg.Wait can't fire prematurely between sources.
		wg.Add(1)
		submit(wordlist())
		submit(r.axfrSubdomains(domain))
		// The apex's own certificate is usually the richest SAN source; probe
		// it directly and emit it so its cert is shown too.
		if certs {
			if leaf := r.fetchCert(domain); leaf != nil {
				foundCh <- Subdomain{Name: domain, IPs: r.resolveHost(domain), Cert: certInfo(leaf)}
				submit(certCandidates(leaf.DNSNames, domain))
			}
		}
		wg.Done()

		wg.Wait()
		close(jobs)
	}()

	return foundCh, progCh
}

// resolveHost returns the A/AAAA addresses (and any CNAME targets in the
// chain) for a host, deduplicated, or nil if it does not resolve.
func (r *Resolver) resolveHost(host string) []string {
	seen := map[string]bool{}
	var ips []string
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		recs, err := r.Query(host, qt)
		if err != nil {
			continue
		}
		for _, rec := range recs {
			if !seen[rec] {
				seen[rec] = true
				ips = append(ips, rec)
			}
		}
	}
	return ips
}
