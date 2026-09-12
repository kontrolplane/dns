package scan

import (
	"crypto/tls"
	"net/http"
	"time"
)

// probeTimeout bounds a single reachability request.
const probeTimeout = 5 * time.Second

// httpClient is shared by every probe so connections, TLS sessions and the
// idle pool are reused across hosts. A client built per call reuses nothing
// and leaves its idle connections for the collector.
//
// Redirects are not followed — the first response status is the signal — and
// invalid TLS certificates are accepted, since recon cares whether the host
// answers at all, not whether its cert is valid.
var httpClient = &http.Client{
	Timeout: probeTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 4,
	},
}

// Reach is the outcome of an HTTP(S) reachability probe against a host.
type Reach struct {
	Scheme string // "https" or "http"; empty if the host answered on neither
	Status int    // HTTP status code; 0 if unreachable
}

// Reachable reports whether the host answered an HTTP request.
func (r Reach) Reachable() bool { return r.Status != 0 }

// ProbeHTTP checks whether host serves HTTP. Both schemes are tried at once
// and HTTPS is preferred when it answers, so a host speaking neither costs a
// single timeout rather than two in series.
func ProbeHTTP(host string) Reach {
	secure, plain := make(chan Reach, 1), make(chan Reach, 1)
	go func() { secure <- get("https", host) }()
	go func() { plain <- get("http", host) }()

	if r := <-secure; r.Reachable() {
		return r
	}
	return <-plain
}

// get performs one request and reduces it to a Reach.
func get(scheme, host string) Reach {
	resp, err := httpClient.Get(scheme + "://" + host)
	if err != nil {
		return Reach{}
	}
	resp.Body.Close()
	return Reach{Scheme: scheme, Status: resp.StatusCode}
}
