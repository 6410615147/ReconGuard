package scanner

import (
    "fmt"
	"net"
	"strings"
	"time"
)

func getServiceInfo(port int) (string, string) {
    switch port {
    case 80:
        return getHTTPServerInfo(port)
    case 22:
        return getSSHServerInfo(port)
    default:
        return "Unknown", "Unknown"
    }
}

func (ps *PortScanner) getHTTPServerInfo(port int) (string, string) {
	address := fmt.Sprintf("%s:%d", ps.TargetHost, port)
    conn, err := net.DialTimeout("tcp", address, 1*time.Second)
    if err != nil {
        return "HTTP", "Unknown"
    }
    defer conn.Close()

    fmt.Fprintf(conn, "HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n", ps.TargetHost)
    buf := make([]byte, 4096)
    n, err := conn.Read(buf)
    if err != nil {
        return "HTTP", "Unknown"
    }

    response := string(buf[:n])
    serverHeader := extractHeaderValue(response, "Server")
    if serverHeader != "" {
        return "HTTP", serverHeader
    }
    return "HTTP", "Unknown"
}

func (ps *PortScanner) getSSHServerInfo(port int) (string, string) {
    address := fmt.Sprintf("%s:%d", ps.TargetHost, port)
	conn, err := net.DialTimeout("tcp", address, 1*time.Second)
	if err != nil {
		return "Unknown", "Unknown"
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "Unknown", "Unknown"
	}

	response := string(buf[:n])
	serverInfo := extractHeaderValue(response, "SSH")
	return "SSH", serverInfo
}

func extractHeaderValue(response, header string) string {
    lines := strings.Split(response, "\r\n")
    for _, line := range lines {
        if strings.HasPrefix(line, header+":") {
            parts := strings.SplitN(line, ":", 2)
            if len(parts) == 2 {
                return strings.TrimSpace(parts[1])
            }
        }
    }
    return "Unknown"
}