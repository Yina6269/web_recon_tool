package vulncheck

import (
	"bytes"
	"fmt"
	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"os"
	"os/exec"
	"strings"
	"web_Recon_tool/shodan"
)

// Vulnerability represents a detected vulnerability on a specific port.
type Vulnerability struct {
	Description string
	Details     string
}

// Display banner for vulnerability checking
func displayBanner() {
	banner := figure.NewColorFigure("Vuln Checker", "straight", "green", true)
	color.Cyan("-------------------------")
	banner.Print()
	color.Cyan("-------------------------")
}

// CheckVulnerabilities initiates a vulnerability scan on open ports and returns a formatted report.
func CheckVulnerabilities(target string, openPorts []int) map[int][]Vulnerability {
	displayBanner()
	color.Cyan("Checking for vulnerabilities on open ports...\n")

	vulns := make(map[int][]Vulnerability)

	if len(openPorts) == 0 {
		color.Yellow("No open ports to check. Exiting vulnerability scan.")
		return vulns
	}

	for _, port := range openPorts {
		fmt.Printf("\nChecking vulnerabilities for port %d...\n", port)

		// Run an Nmap scan for each port
		nmapOutput := runNmap(target, port)

		// Parse and store vulnerabilities in the map
		portVulns := parseNmapOutput(nmapOutput, port)
		if len(portVulns) > 0 {
			vulns[port] = portVulns
		}

		 apiKey := os.Getenv("SHODAN_API_KEY")
             if apiKey == "" {
             panic("Shodan API key not set")
    } 

		hostInfo, err := shodan.GetShodanInfo(apiKey, target)
		if err != nil {
			color.Red("Error: %v", err)
			return nil
		}

		
		shodan.DisplayHostInfo(hostInfo)

	}

	color.Cyan("Vulnerability scan completed. Please review the identified vulnerabilities.")
	return vulns
}

func runNmap(target string, port int) string {
	cmd := exec.Command("nmap", "-sV", "--script", "vuln", "-p", fmt.Sprint(port), target)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		color.Red("Error running Nmap: %v", err)
		return ""
	}
	return out.String()
}

func parseNmapOutput(output string, port int) []Vulnerability {
	var vulnerabilities []Vulnerability

	if output == "" {
		return vulnerabilities
	}

	lines := strings.Split(output, "\n")
	var currentVuln Vulnerability

	for _, line := range lines {
		// Look for a line indicating a vulnerability
		if strings.Contains(line, "VULNERABLE") {
			if currentVuln.Description != "" {
				// Save the previous vulnerability before starting a new one
				vulnerabilities = append(vulnerabilities, currentVuln)
				currentVuln = Vulnerability{}
			}
			currentVuln.Description = line
		} else if strings.Contains(line, "PORT") || strings.Contains(line, "SERVICE") {
			// Collect details related to the vulnerability
			currentVuln.Details += line + "\n"
		}
	}

	// If we have a current vulnerability left at the end, append it
	if currentVuln.Description != "" {
		vulnerabilities = append(vulnerabilities, currentVuln)
	}

	return vulnerabilities
}
