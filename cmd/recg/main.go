package main

import (
	"flag"
	"fmt"
	"recg/internal/scanner"
)

func main() {

	fmt.Println("Welcome to ReconGuard")

	// Define flags for command-line options
	targetHost := flag.String("host", "localhost", "Target host to scan")
	portRange := flag.String("p", "1-1024", "Port range to scan (e.g., '80' or '80-100')")

	// Parse command-line flags
	flag.Parse()

	// Create a map to associate flags with functions
	flagHandlers := map[*flag.Flag]func(){
		flag.Lookup("p"): func() { port_flag(*targetHost, *portRange) },
	}

	// Iterate over defined flags and call corresponding functions
	flag.Visit(func(f *flag.Flag) {
		if handler, ok := flagHandlers[f]; ok {
			handler()
		}
	})
}

func port_flag(target string, portRange string) {

	// Parse the port range string
	startPort, endPort, err := scanner.ParsePortRange(portRange)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Generate the list of ports to scan
	ports := scanner.GeneratePortRange(startPort, endPort)

	// Create a new PortScanner instance
	portScanner := scanner.NewPortScanner(target, ports)

	// Perform port scanning
	portScanner.Scan()
}
