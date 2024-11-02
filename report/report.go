package report

import (
	"fmt"
	"os"
	"web_Recon_tool/portscanner"
	"web_Recon_tool/subdomain"
	"web_Recon_tool/vulncheck"
)

// DirectoryReport holds the discovered directories information.
type DirectoryReport struct {
	Target    string
	FoundDirs []string
	NotFound  []string
}

// WriteReport generates a detailed report on subdomains, open ports, vulnerabilities, and directories.
func WriteReport(domain string, subdomainResults []subdomain.SubdomainResult, result portscanner.PortScanResult, vulns map[int][]vulncheck.Vulnerability, dirReport DirectoryReport) {
	filename := fmt.Sprintf("%s_report.md", domain)
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating report file:", err)
		return
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Println("Error closing file:", err)
		}
	}(file)

	// Write report header
	_, err = file.WriteString(fmt.Sprintf("# Report for %s\n\n", domain))
	if err != nil {
		return
	}

	// Subdomain Enumeration
	_, err = file.WriteString("## Subdomain Enumeration:\n")
	if err != nil {
		return
	}
	for _, result := range subdomainResults {
		_, err := file.WriteString(fmt.Sprintf("- %s.%s: %s\n", result.Subdomain, domain, result.Status))
		if err != nil {
			return
		}
	}

	// Open Ports
	_, err = file.WriteString("\n## Open Ports:\n")
	if err != nil {
		return
	}
	for _, port := range result.OpenPorts {
		_, err := file.WriteString(fmt.Sprintf("- Port %d: open\n", port))
		if err != nil {
			return
		}
	}

	// Vulnerabilities
	_, err = file.WriteString("\n## Vulnerabilities:\n")
	if err != nil {
		return
	}
	for port, vulnList := range vulns {
		_, err := file.WriteString(fmt.Sprintf("\n- Port %d:\n", port))
		if err != nil {
			return
		}
		for _, vuln := range vulnList {
			_, err := file.WriteString(fmt.Sprintf("  * %s\n", vuln.Description))
			if err != nil {
				return
			}
			_, err = file.WriteString(fmt.Sprintf("    Details: %s\n", vuln.Details))
			if err != nil {
				return
			}
		}
	}

	// Directory Discovery Results
	_, err = file.WriteString("\n## Directory Discovery:\n")
	if err != nil {
		return
	}
	if len(dirReport.FoundDirs) > 0 {
		for _, dir := range dirReport.FoundDirs {
			_, err := file.WriteString(fmt.Sprintf("- Found directory: %s/%s\n", dirReport.Target, dir))
			if err != nil {
				return
			}
		}
	} else {
		_, err = file.WriteString("- No directories found.\n")
		if err != nil {
			return
		}
	}

	if len(dirReport.NotFound) > 0 {
		_, err = file.WriteString("\n### Directories Not Found:\n")
		if err != nil {
			return
		}
		for _, dir := range dirReport.NotFound {
			_, err := file.WriteString(fmt.Sprintf("- %s\n", dir))
			if err != nil {
				return
			}
		}
	}

	fmt.Println("Report successfully written to", filename)
}
