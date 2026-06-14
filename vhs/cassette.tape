# dns — terminal-based DNS & subdomain explorer
# Generates the main demo GIF for the README.

Output assets/cassette.gif

Require go

Set FontSize 16
Set Width 1280
Set Height 800
Set Padding 20
Set TypingSpeed 150ms
Set PlaybackSpeed 0.5

# Build and start the application
Hide
Type "go build -o vhs/dns . && ./vhs/dns"
Enter
Sleep 2s
Show

# -- Input screen --
Sleep 2s

# Type a domain to investigate (reachability + cert harvest are on by default)
Type "cloudflare.com"
Sleep 1s

# Start the scan
Enter
Sleep 2s

# -- Results stream in live --
Sleep 6s

# Scroll through the DNS records and discovered subdomains
Down@500ms 10
Sleep 3s
Down@500ms 10
Sleep 3s

# Back to the top
Up@200ms 20
Sleep 3s

# -- Start a new scan --
Escape
Sleep 1s
Backspace 30
Type "github.com"
Sleep 1s
Enter
Sleep 6s

Down@500ms 8
Sleep 3s

# Exit
Type "q"
Sleep 2s
