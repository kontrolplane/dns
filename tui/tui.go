package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/levi/dns/scan"
)

type state int

const (
	stateInput state = iota
	stateScanning
)

// certIcon marks a host whose TLS certificate was harvested.
const certIcon = "[c]"

// --- styles ---

// Outer padding around the whole view: top and sides, but not the bottom.
const (
	padX = 2
	padY = 1
)

var appStyle = lipgloss.NewStyle().Padding(padY, padX, 0, padX)

// scanStyle pads the results page on all sides, including the bottom, so the
// footer isn't flush against the terminal edge.
var scanStyle = lipgloss.NewStyle().Padding(padY, padX, padY, padX)

// Colors mirror the kontrolplane.dev terminal palette.
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFF1CC")).
			Background(lipgloss.Color("#14325C")).
			Padding(0, 1)

	sectionStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F5C76A")).
			MarginTop(1)

	branchStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F5C76A"))
	rootStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFF1CC"))

	labelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#8EE39E"))
	valueStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFF1CC"))
	dimStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#9A917A"))
	errStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#F58A8A"))
	hostStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#8FB4E8"))

	// Reachability status dot colors: 2xx green, 3xx orange, 4xx/5xx red.
	dotGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("#8EE39E"))
	dotOrange = lipgloss.NewStyle().Foreground(lipgloss.Color("#F5A65B"))
	dotRed    = lipgloss.NewStyle().Foreground(lipgloss.Color("#F58A8A"))
)

// --- messages ---

// Every async message carries the scan generation it belongs to, so results
// from a scan that has since been superseded (esc → new scan) are dropped
// instead of corrupting the current one.
type recordResultMsg struct {
	rs  scan.RecordSet
	ok  bool
	gen int
}
type subFoundMsg struct {
	sub scan.Subdomain
	ok  bool
	gen int
}
type progressMsg struct {
	total int
	ok    bool
	gen   int
}
type reachResultMsg struct {
	host  string
	reach scan.Reach
	gen   int
}
type certResultMsg struct {
	cert scan.CertResult
	ok   bool
	gen  int
}
type serviceResultMsg struct {
	svc scan.ServiceRecord
	ok  bool
	gen int
}

// --- model ---

type model struct {
	resolver *scan.Resolver
	state    state
	gen      int // current scan generation; bumped on every startScan

	input    textinput.Model
	spinner  spinner.Model
	viewport viewport.Model
	ready    bool

	// focus selects the active row on the input page: 0 the domain field,
	// 1 the reachability checkbox, 2 the certificate checkbox.
	focus int

	domain   string
	records  map[string]scan.RecordSet // keyed by type; RecordTypes gives the order
	subs     []scan.Subdomain
	services []scan.ServiceRecord

	recordCh <-chan scan.RecordSet
	foundCh  <-chan scan.Subdomain
	certCh   <-chan scan.CertResult
	svcCh    <-chan scan.ServiceRecord
	progCh   <-chan int

	recordsDone  bool
	subsDone     bool
	certsDone    bool
	servicesDone bool
	progDone     int
	progTotal    int

	reachEnabled bool                  // probe found subdomains over HTTP(S)
	reach        map[string]scan.Reach // results keyed by host
	reachPending int                   // probes still in flight

	certEnabled bool                      // harvest TLS certs and mine SANs (default on)
	certs       map[string]*scan.CertInfo // harvested certificates keyed by host

	saveMsg string // footer feedback after an export (path saved or error)

	width  int
	height int
}

// newModel builds the initial model, optionally pre-seeded with a domain to
// scan immediately. server overrides the upstream nameserver when non-empty.
func newModel(domain, server string) model {
	ti := textinput.New()
	ti.Placeholder = "example.com"
	ti.Prompt = ""
	ti.Focus()
	ti.CharLimit = 253
	ti.Width = 40

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#F5C76A"))

	m := model{
		resolver:     scan.NewResolver(server),
		state:        stateInput,
		input:        ti,
		spinner:      sp,
		progTotal:    scan.WordlistSize(),
		reachEnabled: true,
		certEnabled:  true,
	}
	if domain != "" {
		m.input.SetValue(domain)
	}
	return m
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) startScan() (model, tea.Cmd) {
	m.domain = strings.TrimSpace(m.input.Value())
	if m.domain == "" {
		return m, nil
	}
	m.gen++
	m.state = stateScanning
	m.records = map[string]scan.RecordSet{}
	m.subs = nil
	m.services = nil
	m.recordsDone = false
	m.subsDone = false
	m.certsDone = false
	m.servicesDone = false
	m.progDone = 0
	m.reach = map[string]scan.Reach{}
	m.reachPending = 0
	m.certs = map[string]*scan.CertInfo{}
	m.saveMsg = ""

	// Drain any channels left over from a superseded scan so its worker
	// goroutines unblock and exit instead of leaking on their unread sends.
	var cmds []tea.Cmd
	if m.recordCh != nil {
		cmds = append(cmds, drain(m.recordCh))
	}
	if m.foundCh != nil {
		cmds = append(cmds, drain(m.foundCh))
	}
	if m.certCh != nil {
		cmds = append(cmds, drain(m.certCh))
	}
	if m.svcCh != nil {
		cmds = append(cmds, drain(m.svcCh))
	}
	if m.progCh != nil {
		cmds = append(cmds, drain(m.progCh))
	}

	m.recordCh = m.resolver.AllRecords(m.domain)
	m.svcCh = m.resolver.ProbeServices(m.domain)
	m.foundCh, m.certCh, m.progCh = m.resolver.EnumerateSubdomains(m.domain, m.certEnabled)

	cmds = append(cmds,
		m.spinner.Tick,
		waitRecord(m.recordCh, m.gen),
		waitFound(m.foundCh, m.gen),
		waitCert(m.certCh, m.gen),
		waitService(m.svcCh, m.gen),
		waitProg(m.progCh, m.gen),
	)
	if m.reachEnabled {
		m.reachPending++
		cmds = append(cmds, probeReach(m.domain, m.gen)) // probe the apex too
	}
	return m, tea.Batch(cmds...)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		vpWidth := msg.Width - 2*padX
		// Chrome around the viewport: 3 header lines (title, blank, status) +
		// 1 footer line + 2 blank separators, plus top/bottom outer padding.
		vpHeight := msg.Height - 6 - 2*padY
		if vpHeight < 3 {
			vpHeight = 3
		}
		if !m.ready {
			m.viewport = viewport.New(vpWidth, vpHeight)
			m.ready = true
		} else {
			m.viewport.Width = vpWidth
			m.viewport.Height = vpHeight
		}
		if m.state == stateScanning {
			m.viewport.SetContent(m.renderResults())
		}

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.state == stateScanning || msg.String() == "ctrl+c" {
				return m, tea.Quit
			}
		case "tab", "down":
			if m.state == stateInput {
				m.focus = (m.focus + 1) % 3
				return m, m.syncFocus()
			}
		case "shift+tab", "up":
			if m.state == stateInput {
				m.focus = (m.focus + 2) % 3
				return m, m.syncFocus()
			}
		case " ":
			if m.state == stateInput && m.focus != 0 {
				switch m.focus {
				case 1:
					m.reachEnabled = !m.reachEnabled
				case 2:
					m.certEnabled = !m.certEnabled
				}
				return m, nil
			}
		case "s":
			if m.state == stateScanning {
				if path, err := m.save(); err != nil {
					m.saveMsg = errStyle.Render("save failed: " + err.Error())
				} else {
					m.saveMsg = labelStyle.Render("saved " + path)
				}
				return m, nil
			}
		case "esc":
			if m.state == stateScanning {
				m.state = stateInput
				m.input.Focus()
				return m, textinput.Blink
			}
		case "enter":
			if m.state == stateInput {
				nm, cmd := m.startScan()
				return nm, cmd
			}
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)

	case recordResultMsg:
		if msg.gen != m.gen {
			break // stale result from a superseded scan
		}
		if msg.ok {
			m.records[msg.rs.Type] = msg.rs
			m.refreshViewport()
			cmds = append(cmds, waitRecord(m.recordCh, m.gen))
		} else {
			m.recordsDone = true
		}

	case subFoundMsg:
		if msg.gen != m.gen {
			break // stale result from a superseded scan
		}
		if msg.ok {
			m.subs = append(m.subs, msg.sub)
			if m.reachEnabled {
				m.reachPending++
				cmds = append(cmds, probeReach(msg.sub.Name, m.gen))
			}
			m.refreshViewport()
			cmds = append(cmds, waitFound(m.foundCh, m.gen))
		} else {
			m.subsDone = true
		}

	case certResultMsg:
		if msg.gen != m.gen {
			break // stale result from a superseded scan
		}
		if msg.ok {
			m.certs[msg.cert.Host] = msg.cert.Info
			m.refreshViewport()
			cmds = append(cmds, waitCert(m.certCh, m.gen))
		} else {
			m.certsDone = true
		}

	case serviceResultMsg:
		if msg.gen != m.gen {
			break // stale result from a superseded scan
		}
		if msg.ok {
			m.services = append(m.services, msg.svc)
			m.refreshViewport()
			cmds = append(cmds, waitService(m.svcCh, m.gen))
		} else {
			m.servicesDone = true
		}

	case reachResultMsg:
		if msg.gen != m.gen {
			break // stale result from a superseded scan
		}
		m.reach[msg.host] = msg.reach
		m.reachPending--
		m.refreshViewport()

	case progressMsg:
		if msg.gen != m.gen {
			break // stale result from a superseded scan
		}
		if msg.ok {
			m.progDone++
			m.progTotal = msg.total
			m.refreshViewport()
			cmds = append(cmds, waitProg(m.progCh, m.gen))
		}
	}

	if m.state == stateInput && m.focus == 0 {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		cmds = append(cmds, cmd)
	} else if m.state == stateScanning && m.ready {
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// syncFocus focuses the domain field when it is the active row and blurs it
// otherwise, returning the cursor-blink command when newly focused.
func (m *model) syncFocus() tea.Cmd {
	if m.focus == 0 {
		return m.input.Focus()
	}
	m.input.Blur()
	return nil
}

func (m *model) refreshViewport() {
	if m.ready {
		atBottom := m.viewport.AtBottom()
		m.viewport.SetContent(m.renderResults())
		if atBottom {
			m.viewport.GotoBottom()
		}
	}
}

func (m model) scanning() bool {
	return !m.recordsDone || !m.subsDone || !m.certsDone || !m.servicesDone || m.reachPending > 0
}

// reachTotal is the number of hosts probed for reachability: every found
// subdomain plus the apex domain.
func (m model) reachTotal() int { return len(m.subs) + 1 }

// certCount reports how many harvested certificates we hold (apex + subs).
func (m model) certCount() int { return len(m.certs) }

// reachableCount reports how many probed hosts answered an HTTP request.
func (m model) reachableCount() int {
	n := 0
	for _, r := range m.reach {
		if r.Reachable() {
			n++
		}
	}
	return n
}

func (m model) View() string {
	switch m.state {
	case stateInput:
		return appStyle.Render(m.inputView())
	default:
		return scanStyle.Render(m.scanView())
	}
}

// focusCursor renders a pointer in front of the active row, or aligned blank
// space otherwise.
func focusCursor(on bool) string {
	if on {
		return branchStyle.Render("• ")
	}
	return "  "
}

// checkbox renders a toggle box, filled and green when on.
func checkbox(on bool) string {
	if on {
		return labelStyle.Render("[x]")
	}
	return "[ ]"
}

func (m model) inputView() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(" dns ") + "  " + dimStyle.Render("search through a domain") + "\n\n")
	b.WriteString("Enter a domain to investigate:\n\n")
	b.WriteString(focusCursor(m.focus == 0) + m.input.View() + "\n\n")

	b.WriteString(focusCursor(m.focus == 1) + checkbox(m.reachEnabled) + " " + dimStyle.Render("reachability check (HTTP/S probe of found subdomains)") + "\n")
	b.WriteString(focusCursor(m.focus == 2) + checkbox(m.certEnabled) + " " + dimStyle.Render("certificate harvest (read TLS certs, mine SANs for subdomains)") + "\n\n")
	b.WriteString(dimStyle.Render("↑/↓ move · tab next · space toggle · enter scan · ctrl+c quit"))
	return b.String()
}

func (m model) scanView() string {
	if !m.ready {
		return "initializing..."
	}

	var head strings.Builder
	head.WriteString(titleStyle.Render(" dns ") + "  " + valueStyle.Render(m.domain))
	head.WriteString("  " + dimStyle.Render("via "+m.resolver.Server()) + "\n\n")

	if m.scanning() {
		line := fmt.Sprintf(" scanning  subdomains %d/%d  found %d", m.progDone, m.progTotal, len(m.subs))
		if m.reachEnabled {
			line += fmt.Sprintf("  ·  reachability %d/%d", len(m.reach), m.reachTotal())
		}
		if m.certEnabled {
			line += fmt.Sprintf("  ·  certs %d", m.certCount())
		}
		head.WriteString(m.spinner.View() + dimStyle.Render(line))
	} else {
		line := fmt.Sprintf("  probed %d subdomains  found %d", m.progDone, len(m.subs))
		if m.reachEnabled {
			line += fmt.Sprintf("  ·  %d reachable", m.reachableCount())
		}
		if m.certEnabled {
			line += fmt.Sprintf("  ·  %d certs", m.certCount())
		}
		head.WriteString(labelStyle.Render("✓ done") + dimStyle.Render(line))
	}

	footer := dimStyle.Render("↑/↓ scroll · s save · esc new scan · q quit")
	if m.saveMsg != "" {
		footer += dimStyle.Render("  ·  ") + m.saveMsg
	}

	return head.String() + "\n\n" + m.viewport.View() + "\n\n" + footer
}

// treeNode is one line in the rendered tree, with an optional set of
// children drawn beneath it.
type treeNode struct {
	text     string
	children []*treeNode
}

func (m model) renderResults() string {
	apex := rootStyle.Render(m.domain) + reachDot(m.reach, m.domain, m.reachEnabled)
	if m.reachEnabled {
		apex += "  " + renderReach(m.reach, m.domain)
	}
	root := &treeNode{text: apex}

	// DNS records: one node per type that answered, in the canonical order.
	// Types with nothing to show are collapsed onto a single trailing line —
	// most of the two dozen types queried are absent on any given domain, and
	// a screen of "—" buries the ones that are not.
	records := &treeNode{text: branchStyle.Render("records")}
	var empty []string
	for _, name := range scan.RecordTypes() {
		rs, arrived := m.records[name]
		switch {
		case !arrived:
			empty = append(empty, dimStyle.Render(name))
		case rs.Err != nil:
			records.children = append(records.children, &treeNode{
				text: labelStyle.Render(name) + "  " + errStyle.Render(rs.Err.Error()),
			})
		case len(rs.Records) == 0:
			empty = append(empty, dimStyle.Render(name))
		default:
			node := &treeNode{text: labelStyle.Render(name)}
			for _, rec := range rs.Records {
				node.children = append(node.children, &treeNode{text: valueStyle.Render(rec)})
			}
			records.children = append(records.children, node)
		}
	}
	if len(empty) > 0 {
		label := "no answer"
		if !m.recordsDone {
			label = "pending"
		}
		records.children = append(records.children, &treeNode{
			text: dimStyle.Render(label+"  ") + strings.Join(empty, dimStyle.Render(" · ")),
		})
	}

	// Service names: fixed labels that carry mail, certificate and
	// autoconfiguration records no hostname wordlist would reach.
	services := &treeNode{text: branchStyle.Render(fmt.Sprintf("services (%d)", len(m.services)))}
	for _, svc := range sortedServices(m.services) {
		node := &treeNode{text: hostStyle.Render(svc.Name) + "  " + labelStyle.Render(svc.Type)}
		for _, rec := range svc.Records {
			node.children = append(node.children, &treeNode{text: valueStyle.Render(rec)})
		}
		services.children = append(services.children, node)
	}
	if len(services.children) == 0 {
		msg := "probing..."
		if m.servicesDone {
			msg = "none found"
		}
		services.children = append(services.children, &treeNode{text: dimStyle.Render(msg)})
	}

	// Subdomains: nested by label depth below the apex.
	subs := &treeNode{text: branchStyle.Render(fmt.Sprintf("subdomains (%d)", len(m.subs)))}
	subs.children = buildSubTree(m.domain, m.subs, m.certs, m.reach, m.reachEnabled)
	if len(subs.children) == 0 {
		msg := "probing..."
		if m.subsDone {
			msg = "none discovered"
		}
		subs.children = append(subs.children, &treeNode{text: dimStyle.Render(msg)})
	}

	root.children = []*treeNode{records, services, subs}
	if apex := m.certs[m.domain]; apex != nil {
		root.children = append([]*treeNode{{text: renderCert(apex)}}, root.children...)
	}

	var b strings.Builder
	renderNode(&b, root, "", true, true)
	return b.String()
}

// subNode accumulates discovered hosts into a label hierarchy before
// conversion to treeNodes.
type subNode struct {
	label    string
	name     string // full host, set only on nodes that are a discovered subdomain
	ips      []string
	children map[string]*subNode
}

// buildSubTree groups discovered subdomains into a tree by their labels
// relative to the apex domain (e.g. api.staging nests api under staging).
// When reachOn is set, each discovered host is annotated with its HTTP(S)
// reachability from reach (or a pending marker until its probe returns).
func buildSubTree(domain string, found []scan.Subdomain, certs map[string]*scan.CertInfo, reach map[string]scan.Reach, reachOn bool) []*treeNode {
	root := &subNode{children: map[string]*subNode{}}
	suffix := "." + domain
	for _, s := range found {
		rel := strings.TrimSuffix(s.Name, suffix)
		labels := strings.Split(rel, ".")
		cur := root
		for i := len(labels) - 1; i >= 0; i-- {
			lab := labels[i]
			child, ok := cur.children[lab]
			if !ok {
				child = &subNode{label: lab, children: map[string]*subNode{}}
				cur.children[lab] = child
			}
			cur = child
		}
		cur.ips = s.IPs
		cur.name = s.Name
	}
	return root.toTreeNodes(certs, reach, reachOn)
}

func (n *subNode) toTreeNodes(certs map[string]*scan.CertInfo, reach map[string]scan.Reach, reachOn bool) []*treeNode {
	keys := make([]string, 0, len(n.children))
	for k := range n.children {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]*treeNode, 0, len(keys))
	for _, k := range keys {
		c := n.children[k]
		text := hostStyle.Render(c.label)
		if c.name != "" && certs[c.name] != nil {
			text += " " + labelStyle.Render(certIcon)
		}
		if reachOn && c.name != "" {
			text += reachDot(reach, c.name, reachOn)
		}
		if len(c.ips) > 0 {
			text += "  " + dimStyle.Render(strings.Join(c.ips, ", "))
		}
		if reachOn && c.name != "" {
			text += "  " + renderReach(reach, c.name)
		}
		node := &treeNode{text: text, children: c.toTreeNodes(certs, reach, reachOn)}
		out = append(out, node)
	}
	return out
}

// sortedServices orders service results by name then type, so the pane is
// stable however the concurrent probes happen to return.
func sortedServices(svcs []scan.ServiceRecord) []scan.ServiceRecord {
	out := append([]scan.ServiceRecord(nil), svcs...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// renderCert formats a one-line certificate summary: issuer, expiry date,
// and SAN count.
func renderCert(ci *scan.CertInfo) string {
	issuer := ci.Issuer
	if issuer == "" {
		issuer = "unknown issuer"
	}
	return labelStyle.Render("cert") + "  " + dimStyle.Render(fmt.Sprintf(
		"%s · exp %s · %d SANs", issuer, ci.Expires.Format("2006-01-02"), len(ci.SANs)))
}

// reachStyle picks the color for a reachability result: green 2xx, orange
// 3xx, red 4xx/5xx, dim for unreachable.
func reachStyle(r scan.Reach) lipgloss.Style {
	switch {
	case !r.Reachable():
		return dimStyle
	case r.Status >= 400:
		return dotRed
	case r.Status >= 300:
		return dotOrange
	default:
		return dotGreen
	}
}

// reachDot renders a colored status dot for host, placed right after a name:
// a filled dot colored by status class, a dim dot for unreachable, or a
// hollow dim circle while the probe is still in flight. Empty when checks
// are off.
func reachDot(reach map[string]scan.Reach, host string, reachOn bool) string {
	if !reachOn {
		return ""
	}
	r, ok := reach[host]
	if !ok {
		return " " + dimStyle.Render("○")
	}
	return " " + reachStyle(r).Render("●")
}

// renderReach formats the textual reachability annotation for host: a pending
// marker while its probe is in flight, then the scheme and status code, or a
// dim "unreachable".
func renderReach(reach map[string]scan.Reach, host string) string {
	r, ok := reach[host]
	if !ok {
		return dimStyle.Render("checking…")
	}
	if !r.Reachable() {
		return dimStyle.Render("unreachable")
	}
	return reachStyle(r).Render(fmt.Sprintf("%s %d", r.Scheme, r.Status))
}

// renderNode writes n and its descendants with box-drawing connectors.
func renderNode(b *strings.Builder, n *treeNode, prefix string, isLast, isRoot bool) {
	if isRoot {
		b.WriteString(n.text + "\n")
	} else {
		connector := "├─ "
		if isLast {
			connector = "└─ "
		}
		b.WriteString(prefix + dimStyle.Render(connector) + n.text + "\n")
	}

	childPrefix := prefix
	if !isRoot {
		if isLast {
			childPrefix += "   "
		} else {
			childPrefix += dimStyle.Render("│") + "  "
		}
	}
	for i, c := range n.children {
		renderNode(b, c, childPrefix, i == len(n.children)-1, false)
	}
}

// --- channel-reading commands ---

// probeReach runs an HTTP(S) reachability check for host in the background,
// delivering the outcome as a reachResultMsg tagged with the scan generation.
func probeReach(host string, gen int) tea.Cmd {
	return func() tea.Msg {
		return reachResultMsg{host: host, reach: scan.ProbeHTTP(host), gen: gen}
	}
}

func waitRecord(ch <-chan scan.RecordSet, gen int) tea.Cmd {
	return func() tea.Msg {
		rs, ok := <-ch
		return recordResultMsg{rs: rs, ok: ok, gen: gen}
	}
}

func waitFound(ch <-chan scan.Subdomain, gen int) tea.Cmd {
	return func() tea.Msg {
		sub, ok := <-ch
		return subFoundMsg{sub: sub, ok: ok, gen: gen}
	}
}

func waitCert(ch <-chan scan.CertResult, gen int) tea.Cmd {
	return func() tea.Msg {
		cert, ok := <-ch
		return certResultMsg{cert: cert, ok: ok, gen: gen}
	}
}

func waitService(ch <-chan scan.ServiceRecord, gen int) tea.Cmd {
	return func() tea.Msg {
		svc, ok := <-ch
		return serviceResultMsg{svc: svc, ok: ok, gen: gen}
	}
}

func waitProg(ch <-chan int, gen int) tea.Cmd {
	return func() tea.Msg {
		total, ok := <-ch
		return progressMsg{total: total, ok: ok, gen: gen}
	}
}

// drain empties a channel left behind by a superseded scan, letting its
// producing goroutines finish their pending sends and exit. It reports no
// message — the results are intentionally discarded.
func drain[T any](ch <-chan T) tea.Cmd {
	return func() tea.Msg {
		for range ch {
		}
		return nil
	}
}

// Run starts the Bubble Tea program. server overrides the upstream
// nameserver when non-empty.
func Run(domain, server string) error {
	p := tea.NewProgram(newModel(domain, server), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
