package main

import (
	"flag"
	"fmt"
	"net/http"
	"os/exec"
	"recg/internal/scanner"
	"strings"
)

func main() {
	fmt.Println("Welcome to ReconGuard")

	// Define flags for command-line options
	targetHost := flag.String("host", "localhost", "Target host to scan")
	portRange := flag.String("p", "1-1023", "Port range to scan (e.g., '80' or '80-100')")
	commonPort := flag.Bool("cp", false, "Scan common ports")

	// Define flag for web server reconnaissance
	targetFlag := flag.String("o", "", "Target website URL")

	// Parse command-line flags
	flag.Parse()

	// Perform web server reconnaissance if -o flag is provided
	if *targetFlag != "" {
		performWebServerReconnaissance(*targetFlag)
	}
	flagHandlers := map[*flag.Flag]func(){
		flag.Lookup("p"): func() { port_flag(*targetHost, *portRange) },
	}

	// Iterate over defined flags and call corresponding functions
	flag.Visit(func(f *flag.Flag) {
		if handler, ok := flagHandlers[f]; ok {
			handler()
		}
		if *commonPort {
			commonPort_flag(*targetHost)
		}
	})
}

func performWebServerReconnaissance(target string) {
	resp, err := http.Get(target)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Server software:", resp.Header.Get("Server"))
	if strings.Contains(target, "http://") {
		target = strings.TrimPrefix(target, "http://")
	} else if strings.Contains(target, "https://") {
		target = strings.TrimPrefix(target, "https://")
	}
	fmt.Println("Updated target URL:", target)
	cmd := exec.Command("nmap", "-O", target)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error executing Nmap command:", err)
		return
	}

	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")

	var cpeLine, osGuessLine string

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.Contains(line, "OS CPE:") {
			cpeLine = line[len("OS CPE:"):]
		} else if strings.Contains(line, "Aggressive OS guesses:") {
			osGuessLine = line[len("Aggressive OS guesses:"):]
		}
	}

	// Print the desired lines
	if cpeLine == "" && osGuessLine == "" {
		fmt.Println("OS Detection: Not Found")
	} else {
		fmt.Println("OS detection: ", cpeLine)
		fmt.Println("OS Guess: ", osGuessLine)
	}
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

func commonPort_flag(target string) {

	// Create a new PortScanner instance
	portScanner := scanner.NewPortScanner(target, nil)

	// Perform port scanning
	portScanner.ScanCommon()
}

// package main

// import (
// 	"flag"
// 	"fmt"
// 	"recg/internal/scanner"
// )

// func main() {
// 	// Define flags for command-line options
// 	targetHost := flag.String("host", "localhost", "Target host to scan")
// 	// Add more flags as needed for other options

// 	// Parse command-line flags
// 	flag.Parse()

// 	// Create a new OSDetector instance
// 	osDetector := scanner.NewOSDetector(*targetHost)

// 	// Perform OS detection
// 	osInfo, err := osDetector.DetectOS()
// 	if err != nil {
// 		fmt.Println("Error:", err)
// 		return
// 	}

// 	// Print the detected OS information
// 	fmt.Printf("Detected OS for %s: %s\n", *targetHost, osInfo)
// }
