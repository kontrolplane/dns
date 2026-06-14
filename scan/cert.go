package scan

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"time"
)

// CertInfo is the digest of a leaf TLS certificate that recon cares about.
type CertInfo struct {
	Issuer  string    // issuer common name (or first organization)
	Expires time.Time // NotAfter
	SANs    []string  // Subject Alternative Name DNS entries
}

// fetchCert performs a TLS handshake with host:443 and returns the leaf
// certificate, or nil if the host doesn't speak TLS there. Verification is
// skipped — we want whatever cert the server presents, valid or not.
func (r *Resolver) fetchCert(host string) *x509.Certificate {
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, "443"), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return certs[0]
}

// certInfo digests a leaf certificate into the fields we display.
func certInfo(leaf *x509.Certificate) *CertInfo {
	issuer := leaf.Issuer.CommonName
	if issuer == "" && len(leaf.Issuer.Organization) > 0 {
		issuer = leaf.Issuer.Organization[0]
	}
	return &CertInfo{
		Issuer:  issuer,
		Expires: leaf.NotAfter,
		SANs:    leaf.DNSNames,
	}
}

// certCandidates extracts label prefixes under domain from a certificate's
// SAN list — the in-app, no-third-party form of certificate-transparency
// discovery. Wildcards and out-of-domain names are dropped.
func certCandidates(sans []string, domain string) []string {
	suffix := "." + domain
	var words []string
	for _, name := range sans {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == domain || !strings.HasSuffix(name, suffix) {
			continue
		}
		word := strings.TrimSuffix(name, suffix)
		if word == "" || strings.Contains(word, "*") {
			continue // bare apex or wildcard — nothing concrete to probe
		}
		words = append(words, word)
	}
	return words
}
