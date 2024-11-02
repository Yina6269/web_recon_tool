package portscanner

import (
	"fmt"
	"github.com/briandowns/spinner"
	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"net"
	"sync"
	"time"
)

// PortScanResult holds the result of a port scan
type PortScanResult struct {
	OpenPorts   []int
	ClosedPorts []int
}

// Display banner for port scanning
func displayBanner() {
	banner := figure.NewColorFigure("Port Scanner", "straight", "yellow", true)
	banner.Print()
}

// Scan performs the port scan on the given target and returns a PortScanResult
func Scan(target string) PortScanResult {
	displayBanner()
	var result PortScanResult
	color.Green("Scanning ports for: %s\n", target)
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Suffix = " Scanning ports...."
	s.Start()
	defer s.Stop()

	var wg sync.WaitGroup
	mu := sync.Mutex{}

	for port := 1; port <= 1024; port++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", target, p)
			conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
			mu.Lock()         // Locking for shared resource
			defer mu.Unlock() // Unlock after finishing

			if err == nil {
				result.OpenPorts = append(result.OpenPorts, p) // Collect open ports
				color.Green("[+] Port %d is open\n", p)
				conn.Close()
			} else {
				result.ClosedPorts = append(result.ClosedPorts, p) // Collect closed ports
				if p%50 == 0 {
					color.Red("[-] Port %d is closed\n", p)
				}
			}
			if p%50 == 0 {
				color.Yellow("[*] Scanning ... %d/%d ports checked\n", p, 1024)
			}
		}(port)
	}
	wg.Wait()
	s.Stop()
	color.Yellow("[*] Scanning completed!\n")

	if len(result.OpenPorts) > 0 {
		color.Green("\nSummary of Open Ports:\n")
		for _, port := range result.OpenPorts {
			color.Green(" - Port %d is open\n", port)
		}
	} else {
		color.Red("No open ports found.\n")
	}

	fmt.Println("Scan finished.")
	return result // Return the structured results
}
