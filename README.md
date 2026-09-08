<p align="center">
  <h1>dns</h1>
</p>

`dns` is a terminal user interface (tui) application that takes a domain name and queries out everything it can find — DNS records across all common types, plus live subdomain enumeration — into a single navigable view. Results stream in as queries complete, making it a fast way to investigate the surface area of any domain directly from the terminal.

Everything runs from your machine against the zone's own nameservers and hosts. There are no third-party APIs, no accounts, and no keys.

## usage

Start on the input screen and type a domain:

```bash
dns
```

Or scan immediately:

```bash
dns example.com
```

Queries use the system's configured nameserver (from `/etc/resolv.conf`), falling back to `1.1.1.1`. Override the upstream nameserver with `-ns`:

```bash
dns -ns 8.8.8.8 example.com
```

The flag takes a bare address or an explicit port (`8.8.8.8` or `8.8.8.8:53`).

## demonstration

`live scan`
<p align="center">
  <img width="2400" alt="dns live scan" src="./assets/cassette.gif">
</p>

`input screen`
<p align="center">
  <img width="2400" alt="dns input screen" src="./assets/pages/scan/input.png">
</p>

`dns records`
<p align="center">
  <img width="2400" alt="dns dns records" src="./assets/pages/scan/records.png">
</p>

`subdomains`
<p align="center">
  <img width="2400" alt="dns subdomains" src="./assets/pages/scan/subdomains.png">
</p>

## what it shows

- **DNS records** — A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA and PTR for the apex domain.
- **Subdomains** — resolves candidate hostnames concurrently and lists those that answer, with their addresses and any CNAME chain. Candidates come from three sources:
  - an embedded wordlist of 500 common hostnames,
  - a zone transfer (`AXFR`) attempt against each authoritative nameserver — nearly always refused, but it yields the entire zone on a misconfigured one,
  - the Subject Alternative Names read off each live host's TLS certificate, fed back in as new candidates. This is certificate-transparency discovery done in-app, without querying a CT log.

Two optional passes are toggled on the input screen:

- **reachability check** — probes each discovered host over HTTPS then HTTP and annotates it with the scheme and status code. Redirects are not followed, so the first response is the signal.
- **certificate harvest** — reads the leaf TLS certificate from each live host and shows its issuer, expiry and SANs. This is also what drives SAN-based subdomain discovery above.

Both accept invalid certificates on purpose: the question is whether a host answers, not whether its certificate validates.

Press `s` at any point during a scan to write the results so far to `dns-<domain>-<timestamp>.json` in the working directory.

## keybindings

**input screen**

- `tab` / `↓`, `shift+tab` / `↑`: move between the domain field and the toggles
- `space`: toggle the focused option
- `enter`: start the scan

**during a scan**

- `↑`, `↓`: scroll results
- `s`: save results to a JSON file
- `esc`: back to the input screen for a new scan
- `q`, `ctrl+c`: quit

## development

Requires [go](https://go.dev/) 1.26+.

```bash
go build -o dns . && ./dns example.com
```

A `Makefile` wraps the common tasks — `make build`, `run`, `test`, `fmt`, `vet` and `clean`.

The readme's preview gif and screenshots are generated with [vhs](https://github.com/charmbracelet/vhs). After a change that affects the interface, regenerate them with:

```bash
make assets
```

Or individually:

```bash
vhs vhs/cassette.tape
vhs vhs/screenshots.tape
```

## contributors

<a href="https://github.com/levivannoort"><img src="https://avatars.githubusercontent.com/u/73097785?v=4" title="levivannoort" width="50" height="50"></a>
