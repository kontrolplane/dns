package scan

import (
	"crypto/tls"
	"net/http"
	"time"
)

// Reach is the outcome of an HTTP(S) reachability probe against a host.
type Reach struct {
	Scheme string // "https" or "http"; empty if the host answered on neither
	Status int    // HTTP status code; 0 if unreachable
}

// Reachable reports whether the host answered an HTTP request.
func (r Reach) Reachable() bool { return r.Status != 0 }

// ProbeHTTP checks whether host serves HTTP, trying HTTPS first then plain
// HTTP. Redirects are not followed — the first response status is the signal
// — and invalid TLS certificates are accepted, since recon cares whether the
// host answers at all, not whether its cert is valid.
func ProbeHTTP(host string) Reach {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	for _, scheme := range []string{"https", "http"} {
		resp, err := client.Get(scheme + "://" + host)
		if err != nil {
			continue
		}
		resp.Body.Close()
		return Reach{Scheme: scheme, Status: resp.StatusCode}
	}
	return Reach{}
}
