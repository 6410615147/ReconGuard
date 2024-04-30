package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"recg/internal/scanner"
	"strings"
)

func main() {
	fmt.Println("Welcome to ReconGuard")

	// Define flags for command-line options
	targetHost := flag.String("host", "localhost", "Target host to scan")
	osFlag := flag.Bool("o", false, "Target website URL")
	portRange := flag.String("p", "1-1023", "Port range to scan (e.g., '80' or '80-100')")
	commonPort := flag.Bool("cp", false, "Scan common ports")
	wordlistSize := flag.String("dirb", "common", "Specify the size of the wordlist (common, medium, large)")
	// Define flag for web server reconnaissance
	targetFlag := flag.String("u", "", "Target website URL")
	scanServices := flag.Bool("sv", false, "Enable service detection")
	// Parse command-line flags
	flag.Parse()
	fmt.Println(osFlag)
	fmt.Println(scanServices)
	// print(portRange)
	// Perform web server reconnaissance if -o flag is provided

	flagHandlers := map[*flag.Flag]func(){
		flag.Lookup("p"): func() { port_flag(*targetHost, *portRange) },
	}

	if flag.Lookup("sv") != nil {
		portScanner := scanner.NewPortScanner(*targetFlag, nil)
		portScanner.ScanWithServiceDetection(*portRange)
	}

	flag.Visit(func(f *flag.Flag) {
		if handler, ok := flagHandlers[f]; ok {
			handler()
		}
		if *commonPort {
			commonPort_flag(*targetFlag)
		}
	})

	if flag.Lookup("o") != nil {

		performWebServerReconnaissance(*targetFlag)
	}
	// --------------------- path --------------
	web := *targetFlag
	fmt.Println(web)

	// Choose wordlist file based on the flag value
	var wordlistPath string
	switch *wordlistSize {
	case "common":
		wordlistPath = "../../wordlists/common.txt"
	case "medium":
		wordlistPath = "../../wordlists/medium.txt"
	case "large":
		wordlistPath = "../../wordlists/large.txt"
	default:
		fmt.Println("Invalid wordlist size specified.")
		return
	}

	// Open the wordlist file
	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// Read lines from the wordlist file
	scanner := bufio.NewScanner(file)
	// fmt.Println("Method 2 Output:")
	var word []string // Slice to store lines from the file
	for scanner.Scan() {
		word = append(word, scanner.Text()) // Append each line to the slice
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error scanning file:", err)
		return
	}

	// Check URLs constructed from the wordlist
	for _, i := range word {
		checkURL(web + "/" + i + "/")
	}
}

func checkURL(url string) {
	resp, err := http.Get(url)
	if err != nil {
		// fmt.Printf("Error accessing %s: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	// Handle different HTTP status codes
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("%s returns status 200 \n", url)
	} else if resp.StatusCode == http.StatusMovedPermanently {
		fmt.Printf("%s returns status 301 \n", url)
	} else if resp.StatusCode == http.StatusFound {
		fmt.Printf("%s returns status 302 \n", url)
	} else if resp.StatusCode == 403 {
		fmt.Printf("%s returns status 403 \n", url)
	}
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

	// fmt.Println("Updated target URL:", target)
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

	// path scan ---------------

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
