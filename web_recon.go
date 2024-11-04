package main

import (
	"flag"
	"github.com/briandowns/spinner"
	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"os"
	"time"
	"web_Recon_tool/directory"
	"web_Recon_tool/httpcheck"
	"web_Recon_tool/portscanner"
	"web_Recon_tool/report"
	"web_Recon_tool/subdomain"
	"web_Recon_tool/vulncheck"
)

// Display banner
func displayBanner() {
	banner := figure.NewColorFigure("Web Recon Tool", "cyberlarge", "cyan", true)
	color.Cyan("------------------------------------------------------------------------------------------------")
	banner.Print()
	color.Green("                                                                      CODED BY: NAOD-ETHIOP")
	color.Cyan("------------------------------------------------------------------------------------------------")
}

func displayUsage() {
	color.Green(`
Web Recon Tool
CODED BY: NAOD-ETHIOP
==============

Usage:
 web_recon  <command> [options]
Note :- make sure to set your shodan api to environment variable 
    windows : use :- $env:SHODAN_API_KEY="your_api_key_here"
    linux : export SHODAN_API_KEY="your_api_key_here"
   
Commands:
  portscan <host>       Perform a port scan on the target host.
  vulncheck <host>      Check for common vulnerabilities on the target host.
  subdomain <host>      Enumerate subdomains of the target host.
  dir <host>            Discover directories of the target host.
  httpcheck <host>      Check HTTP response.

  mode                  Run in a recon mode (full or less).

Options for Mode:
  --mode <full|less>    Choose the recon mode:
                        - full: Performs all recon tasks (port scan, vulnerability check, subdomain enumeration).
                        - less: Runs essential tasks only (like port scan).
  --host <hostname>     Target host for recon in mode.

Examples:
  web_recon   portscan example.com
  web_recon   vulncheck example.com
  web_recon   subdomain example.com
  web_recon   mode --mode full --host example.com
  `)
}

func fullRecon(host string) {
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()
	color.Blue("RUNNING FULL RECON MODE")
	httpcheck.Check(host)
	scanResult := portscanner.Scan(host)
	subdomains := subdomain.Enumerate(host)
	directories := directory.Discover(host)
	vulnerability := vulncheck.CheckVulnerabilities(host, scanResult.OpenPorts)
	report.WriteReport(host, subdomains, scanResult, vulnerability, report.DirectoryReport(directories))
	color.Green("FULL RECON COMPLETED")
	s.Stop()
}

func lessRecon(host string) {
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()
	color.Blue("Running Less Recon Mode")
	scanResult := portscanner.Scan(host)
	vulncheck.CheckVulnerabilities(host, scanResult.OpenPorts)
	color.Green("LESS RECON COMPLETED.")
	s.Stop()
}

func handleVulnCheck(target string) {
	if target == "" {
		color.Red("Error: No target provided.")
		displayUsage()
		os.Exit(1)
	}
	color.Cyan("Starting vulnerability check on target %s", target)
	scanResult := portscanner.Scan(target)

	if len(scanResult.OpenPorts) > 0 {
		vulncheck.CheckVulnerabilities(target, scanResult.OpenPorts)
	} else {
		color.Yellow("No ports detected. Skipping vulnerability check.")
	}
}

func main() {

	port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
	fmt.Printf("Listening on 0.0.0.0:%s\n", port)
	displayBanner()

	if len(os.Args) < 2 {
		color.Red("Error: No command provided.")
		displayUsage()
		os.Exit(1)
	}

	modeFlag := flag.NewFlagSet("mode", flag.ExitOnError)
	mode := modeFlag.String("mode", "full", "Recon mode: 'full' or 'less'")
	host := modeFlag.String("host", "", "Target host for recon in mode")

	command := os.Args[1]
	target := os.Args[2]

	switch command {
	case "subdomain":
		if len(os.Args) < 3 {
			color.Red("Error: No target host provided.")
			displayUsage()
			os.Exit(1)
		}
		subdomain.Enumerate(target)
	case "dir":
		if len(os.Args) < 3 {
			color.Red("Error: No target host provided.")
			displayUsage()
			os.Exit(1)
		}
		directory.Discover(target)
	case "httpcheck":
		if len(os.Args) < 3 {
			color.Red("Error: No target host provided.")
			displayUsage()
			os.Exit(1)
		}
		httpcheck.Check(target)
	case "portscan":
		if len(os.Args) < 3 {
			color.Red("Error: No target host provided.")
			displayUsage()
			os.Exit(1)
		}
		portscanner.Scan(target)
	case "vulncheck":
		if len(os.Args) < 3 {
			color.Red("Error: No target host provided.")
			displayUsage()
			os.Exit(1)
		}
		handleVulnCheck(target)
	case "report":
		if len(os.Args) < 3 {
			color.Red("Error: No target host provided.")
			displayUsage()
			os.Exit(1)
		}
		color.Cyan("Generating report for target %s", target)
		scanResult := portscanner.Scan(target)
		subdomains := subdomain.Enumerate(target)
		directories := directory.Discover(target)
		vulnerability := vulncheck.CheckVulnerabilities(target, scanResult.OpenPorts)

		report.WriteReport(target, subdomains, scanResult, vulnerability, report.DirectoryReport(directories))
		color.Green("Report generation completed.")
	case "mode":
		err := modeFlag.Parse(os.Args[2:])
		if err != nil {
			return
		}
		if *host == "" {
			color.Red("Error: Target host required for mode option.")
			displayUsage()
			os.Exit(1)
		}
		switch *mode {
		case "full":
			fullRecon(*host)
		case "less":
			lessRecon(*host)
		default:
			color.Red("Error: Invalid mode. Use 'full' or 'less'")
			displayUsage()
			os.Exit(1)
		}
	case "help":
		displayUsage()
	default:
		color.Red("Error: Unknown command:", command)
		displayUsage()
		os.Exit(1)
	}
}
