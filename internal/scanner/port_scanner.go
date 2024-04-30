package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// PortScanner represents a port scanning functionality
type PortScanner struct {
	TargetHost string
	Ports      []int
}

// NewPortScanner creates a new PortScanner instance with the given target host and ports
func NewPortScanner(targetHost string, ports []int) *PortScanner {
	return &PortScanner{
		TargetHost: targetHost,
		Ports:      ports,
	}
}

// Scan scans the specified ports on the target host
func (ps *PortScanner) Scan() {
	fmt.Println("Starting reconaissance...")
	fmt.Printf("RecG report for %s\n", ps.TargetHost)
	fmt.Println("PORT\tSTATUS")

	for _, port := range ps.Ports {
		// Perform port scanning for each port
		address := fmt.Sprintf("%s:%d", ps.TargetHost, port)
		_, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			fmt.Printf("Port %d open\n", port)
		}
		time.Sleep(10000)
	}
}

// ScanRange scans ports within the specified range on the target host
func (ps *PortScanner) ScanRange(startPort, endPort int) {
	fmt.Println("Starting reconaissance...")
	fmt.Printf("RecG report for %s within range %d-%d...\n", ps.TargetHost, startPort, endPort)

	for port := startPort; port <= endPort; port++ {
		// Perform port scanning for each port
		address := fmt.Sprintf("%s:%d", ps.TargetHost, port)
		_, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			fmt.Printf("Port %d open\n", port)
		}
	}
}

// ScanCommon scans commonly used ports on the target host
func (ps *PortScanner) ScanCommon() {
	commonPorts := []int{21, 22, 23, 25, 53, 80, 443, 445, 3389} // Example list of commonly used ports
	ps.ScanPorts(commonPorts)
}

// ScanPorts scans the specified ports on the target host
func (ps *PortScanner) ScanPorts(ports []int) {
	fmt.Println("Starting reconaissance...")
	fmt.Printf("RecG report for %s\n", ps.TargetHost)
	fmt.Println("PORT\tSTATUS")

	for _, port := range ports {
		// Perform port scanning for each port
		address := fmt.Sprintf("%s:%d", ps.TargetHost, port)
		_, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			fmt.Printf("Port %d open\n", port)
		}
	}
}

// GeneratePortRange generates a range of ports from startPort to endPort
func GeneratePortRange(startPort, endPort int) []int {
	var ports []int
	for port := startPort; port <= endPort; port++ {
		ports = append(ports, port)
	}
	return ports
}

// ParsePortRange parses a port range string (e.g., "80-100") into start and end ports
func ParsePortRange(portRange string) (startPort, endPort int, err error) {
	ports := strings.Split(portRange, "-")
	if len(ports) != 2 {
		return 0, 0, fmt.Errorf("invalid port range format")
	}

	startPort, err = strconv.Atoi(ports[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port: %v", err)
	}

	endPort, err = strconv.Atoi(ports[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port: %v", err)
	}

	return startPort, endPort, nil
}

func (ps *PortScanner) ScanWithServiceDetection(portRange string) {
	startPort, endPort, err := ParsePortRange(portRange)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	ports := GeneratePortRange(startPort, endPort)

	fmt.Println("Starting reconnaissance...")
	fmt.Printf("RecG report for %s\n", ps.TargetHost)
	fmt.Println("PORT\tSTATUS\tSERVICE\tVERSION")

	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", ps.TargetHost, port)
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err != nil {
            continue // Skip to the next port if connection failed
        }
        defer conn.Close()

        fmt.Printf("Port %d open\n", port)
        serviceName, serviceVersion := getServiceInfo(port)
        fmt.Printf("\tService: %s\n", serviceName)
        fmt.Printf("\tVersion: %s\n", serviceVersion)
	}
}