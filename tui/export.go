package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/levi/dns/scan"
)

// snapshot is the JSON shape written by an export. It mirrors the model's
// results but flattens record errors to strings (an error value marshals to
// an empty object) and only includes reachability when it was enabled.
type snapshot struct {
	Domain     string          `json:"domain"`
	Nameserver string          `json:"nameserver"`
	ScannedAt  string          `json:"scanned_at"`
	Records    []recordExport  `json:"records"`
	ApexCert   *scan.CertInfo  `json:"apex_cert,omitempty"`
	Services   []serviceExport `json:"services,omitempty"`
	Subdomains []subExport     `json:"subdomains"`
}

type serviceExport struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Records []string `json:"records"`
}

type recordExport struct {
	Type    string   `json:"type"`
	Records []string `json:"records,omitempty"`
	Error   string   `json:"error,omitempty"`
}

type subExport struct {
	Name  string         `json:"name"`
	IPs   []string       `json:"ips,omitempty"`
	Cert  *scan.CertInfo `json:"cert,omitempty"`
	Reach *reachExport   `json:"reach,omitempty"`
}

type reachExport struct {
	Scheme string `json:"scheme"`
	Status int    `json:"status"`
}

// save writes a JSON snapshot of the current results to a timestamped file in
// the working directory and returns the path written.
func (m model) save() (string, error) {
	now := time.Now()

	snap := snapshot{
		Domain:     m.domain,
		Nameserver: m.resolver.Server(),
		ScannedAt:  now.Format(time.RFC3339),
		ApexCert:   m.certs[m.domain],
	}

	// Records and subdomains arrive concurrently; emit both in a stable order
	// so two exports of the same zone diff cleanly.
	for _, name := range scan.RecordTypes() {
		rs, ok := m.records[name]
		if !ok {
			continue
		}
		re := recordExport{Type: name, Records: rs.Records}
		if rs.Err != nil {
			re.Error = rs.Err.Error()
		}
		snap.Records = append(snap.Records, re)
	}

	for _, svc := range sortedServices(m.services) {
		snap.Services = append(snap.Services, serviceExport{
			Name: svc.Name, Type: svc.Type, Records: svc.Records,
		})
	}

	subs := append([]scan.Subdomain(nil), m.subs...)
	sort.Slice(subs, func(i, j int) bool { return subs[i].Name < subs[j].Name })

	for _, s := range subs {
		se := subExport{Name: s.Name, IPs: s.IPs, Cert: m.certs[s.Name]}
		if m.reachEnabled {
			if r, ok := m.reach[s.Name]; ok && r.Reachable() {
				se.Reach = &reachExport{Scheme: r.Scheme, Status: r.Status}
			}
		}
		snap.Subdomains = append(snap.Subdomains, se)
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return "", err
	}

	path := fmt.Sprintf("dns-%s-%s.json", m.domain, now.Format("20060102-150405"))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}
