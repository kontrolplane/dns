# dns — screenshot captures for README.
# Generates individual PNG screenshots of key screens.

Require go

Set FontSize 16
Set Width 1280
Set Height 800
Set Padding 20

# Build and start the application
Hide
Type "go build -o vhs/dns . && ./vhs/dns"
Enter
Sleep 2s
Show

# -- Screenshot 1: Input screen --
Sleep 1s
Type "kontrolplane.dev"
Sleep 500ms
Screenshot assets/pages/scan/input.png

# Run a scan (reachability + cert harvest are on by default)
Sleep 500ms
Enter

# -- Screenshot 2: DNS records --
Sleep 10ms
Screenshot assets/pages/scan/records.png
Sleep 500ms

# Start a new scan to capture a domain with rich subdomains
Escape
Sleep 500ms
Backspace 30
Type "cloudflare.com"
Sleep 500ms
Enter
Sleep 6s

# Jump to the bottom of the results — the discovered subdomains
Hide
Type "G"
Show
Sleep 1s

# -- Screenshot 3: Subdomains --
Screenshot assets/pages/scan/subdomains.png
Sleep 500ms

# Exit
Type "q"
Sleep 500ms
