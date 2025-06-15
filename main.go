package main

import ( "bufio" "crypto/tls" "fmt" "net" "os" "strings" "time" )

const ( NmapOutputFile     = "nmap_output.txt" WorkingOutputFile  = "working_sni_hosts.txt" )

// Extract live hosts from nmap_output.txt func extractLiveHosts(filename string) ([]string, error) { file, err := os.Open(filename) if err != nil { return nil, err } defer file.Close()

hosts := make(map[string]bool)
scanner := bufio.NewScanner(file)
for scanner.Scan() {
	line := scanner.Text()
	if strings.Contains(line, "443/open") && strings.Contains(line, "Host:") {
		fields := strings.Fields(line)
		if len(fields) > 1 {
			hosts[fields[1]] = true
		}
	}
}

var result []string
for host := range hosts {
	result = append(result, host)
}
return result, nil

}

// Perform TLS handshake using SNI func checkSNI(host string) bool { dialer := &net.Dialer{ Timeout: 5 * time.Second, }

conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
	ServerName:         host,
	InsecureSkipVerify: true, // Don't verify cert chain
})
if err != nil {
	fmt.Printf("\u274C [INVALID] %s | Error: %v\n", host, err)
	return false
}
defer conn.Close()

cert := conn.ConnectionState().PeerCertificates[0]
fmt.Printf("\u2705 [VALID] %s | CN: %s\n", host, cert.Subject.CommonName)
return true

}

func main() { if _, err := os.Stat(NmapOutputFile); os.IsNotExist(err) { fmt.Println("\u274C Nmap output file not found!") return }

fmt.Println("\U0001F4E1 Extracting live hosts from Nmap...")
hosts, err := extractLiveHosts(NmapOutputFile)
if err != nil {
	fmt.Printf("Error reading hosts: %v\n", err)
	return
}

fmt.Printf("\U0001F3AF Found %d hosts to test...\n\n", len(hosts))
var working []string

for _, host := range hosts {
	if checkSNI(host) {
		working = append(working, host)
	}
}

if len(working) > 0 {
	f, err := os.Create(WorkingOutputFile)
	if err != nil {
		fmt.Printf("Failed to save working hosts: %v\n", err)
		return
	}
	defer f.Close()

	for _, h := range working {
		f.WriteString(h + "\n")
	}
	fmt.Printf("\n\u2705 Saved %d working SNI hosts to: %s\n", len(working), WorkingOutputFile)
} else {
	fmt.Println("\u274C No working bug hosts found.")
}

}

