package main

import (
	"flag"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

func main() {
	// Define command-line flags
	targetFlag := flag.String("o", "", "Target website URL")
	flag.Parse()

	// Check if targetFlag is provided
	if *targetFlag == "" {
		fmt.Println("Please provide a target website URL using the -o flag")
		return
	}

	target := *targetFlag
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
			// print(line[len("OS CPE:"):])
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
