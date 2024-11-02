package subdomain

import (
	"fmt"
	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"io"
	"net/http"
	"sync"
	"time"
)

// Display banner for subdomain enumeration
func displayBanner() {
	banner := figure.NewColorFigure("Subdomain Enumeration", "straight", "cyan", true)
	color.Cyan("-----------------------------")
	banner.Print()
	color.Cyan("-----------------------------\n")
}

// SubdomainResult stores information about each enumerated subdomain.
type SubdomainResult struct {
	Subdomain string
	Status    string
}

// List of common subdomains to check
var subdomains = []string{
	"www", "mail", "blog", "dev", "test", "admin", "api", "shop", "staging",
	// Additional entries...
}

const maxConcurrency = 20

// Enumerate scans for active subdomains and returns structured results for reporting.
func Enumerate(domain string) []SubdomainResult {
	displayBanner()
	var results []SubdomainResult
	var wg sync.WaitGroup
	subenum := make(chan struct{}, maxConcurrency)
	mu := &sync.Mutex{}
	client := &http.Client{Timeout: 5 * time.Second}

	const maxNoResponseDisplay = 50
	noResponseCount := 0
	color.Cyan("Enumerating subdomains for: %s\n", domain)

	checkSubdomain := func(sub string) {
		defer wg.Done()
		subenum <- struct{}{}
		defer func() { <-subenum }()
		url := "https://" + sub + "." + domain
		resp, err := client.Get(url)
		if err != nil {
			mu.Lock()
			if noResponseCount < maxNoResponseDisplay {
				color.Red("%s: no response", sub)
			}
			noResponseCount++
			results = append(results, SubdomainResult{Subdomain: sub, Status: "No Response"})
			mu.Unlock()
			return
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				color.Red("Error closing response body: %v", err)
			}
		}(resp.Body)

		status := resp.Status
		mu.Lock()
		if resp.StatusCode == http.StatusOK {
			color.Green("Found subdomain: %s.%s - %s", sub, domain, status)
			results = append(results, SubdomainResult{Subdomain: sub, Status: status})
		} else {
			color.Yellow("%s: %s", sub, status)
			results = append(results, SubdomainResult{Subdomain: sub, Status: status})
		}
		mu.Unlock()
	}

	for _, sub := range subdomains {
		wg.Add(1)
		go checkSubdomain(sub)
	}
	wg.Wait()

	if len(results) > 0 {
		color.Cyan("\nEnumeration completed.")
		for _, result := range results {
			if result.Status != "No Response" {
				link := fmt.Sprintf("https://%s.%s", result.Subdomain, domain)
				color.Green("\x1b]8;;%s\x1b\\- %s.%s (%s)\x1b]8;;\x1b\\", link, result.Subdomain, domain, result.Status)
			}
		}
	} else {
		color.Yellow("\nEnumeration completed. No open subdomains found.")
	}

	return results
}
