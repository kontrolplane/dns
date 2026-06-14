package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/levi/dns/tui"
)

func main() {
	ns := flag.String("ns", "", "upstream nameserver to query (e.g. 8.8.8.8 or 8.8.8.8:53); defaults to the system resolver")
	flag.Parse()

	domain := flag.Arg(0)
	if err := tui.Run(domain, *ns); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
