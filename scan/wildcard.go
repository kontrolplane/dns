package scan

import (
	"math/rand/v2"

	"github.com/miekg/dns"
)

// wildcardProbes is how many improbable labels are resolved to profile a zone.
// More than one guards against a single unlucky collision or a dropped reply.
const wildcardProbes = 3

// wildcard records how a zone answers names that do not exist. Both facts are
// needed before any candidate's answer can be trusted:
//
//   - addrs holds whatever a zone with a `*` record synthesises for arbitrary
//     names. Without it every candidate looks like a hit, and the certificate
//     feedback loop then amplifies the noise.
//   - nxdomain reports whether absent names are denied properly. Several large
//     providers sign with minimally covering NSEC and answer NOERROR for
//     everything, which makes "exists but has no address" meaningless there.
type wildcard struct {
	addrs    map[string]bool
	nxdomain bool
}

// profileWildcard resolves a few random labels under domain to learn how the
// zone answers names that cannot exist.
func (r *Resolver) profileWildcard(domain string) wildcard {
	wc := wildcard{addrs: map[string]bool{}, nxdomain: true}
	for i := 0; i < wildcardProbes; i++ {
		host := randomLabel() + "." + domain
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			resp, err := r.exchange(question(host, qt))
			if err != nil {
				continue
			}
			if resp.Rcode != dns.RcodeNameError {
				wc.nxdomain = false
			}
			for _, rr := range resp.Answer {
				wc.addrs[formatRR(rr)] = true
			}
		}
	}
	return wc
}

// synthesised reports whether an answer set is indistinguishable from what the
// zone returns for a name that does not exist. A real host sitting behind the
// same load balancer as the wildcard is rejected along with the noise; that
// trade is worth it against reporting an entire wordlist as found.
func (wc wildcard) synthesised(recs []string) bool {
	if len(wc.addrs) == 0 {
		return false
	}
	for _, rec := range recs {
		if !wc.addrs[rec] {
			return false
		}
	}
	return true
}

// randomLabel builds a label long enough that a zone is most unlikely to have
// it registered.
func randomLabel() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = alphabet[rand.IntN(len(alphabet))]
	}
	return string(b)
}
