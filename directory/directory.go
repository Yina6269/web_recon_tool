package directory

import (
	"fmt"
	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Display banner for directory discovery
func displayBanner() {
	banner := figure.NewColorFigure("Directory Discovery", "straight", "green", true)
	banner.Print()
}

var directories = []string{
	// (same as before)
	// Example entries
	"admin", "login", "uploads", "images", "api",
	// ... (list of directories)
}

const maxConcurrency = 30

// Report structure for directories discovered
type Report struct {
	Target    string
	FoundDirs []string
	NotFound  []string
}

func Discover(target string) Report {
	displayBanner()
	var openDirectory []string
	var notFound []string
	var wg sync.WaitGroup
	direc := make(chan struct{}, maxConcurrency)
	mu := &sync.Mutex{}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target // Default to http if no prefix is present
	}
	client := &http.Client{Timeout: 5 * time.Second}

	const maxNoResponseDisplay = 50
	noResponseCount := 0

	color.Cyan("Discovering directories for: %s", target)

	checkDirectory := func(dir string) {
		defer wg.Done()
		direc <- struct{}{}
		defer func() { <-direc }()
		url := target + "/" + dir
		resp, err := client.Get(url)
		if err != nil {
			mu.Lock()
			if noResponseCount < maxNoResponseDisplay {
				color.Red("[-] %s: no response", dir)
			}
			noResponseCount++
			mu.Unlock()
			return
		}
		defer resp.Body.Close()

		mu.Lock()
		if resp.StatusCode == http.StatusOK {
			color.Green("[+] Found directory: %s/%s - %s", target, dir, resp.Status)
			openDirectory = append(openDirectory, dir)
		} else {
			color.Yellow("%s: %s", dir, resp.Status)
			notFound = append(notFound, dir)
		}
		mu.Unlock()
	}

	for _, dir := range directories {
		wg.Add(1)
		go checkDirectory(dir)
	}
	wg.Wait()

	// Prepare and return the formatted report
	report := Report{
		Target:    target,
		FoundDirs: openDirectory,
		NotFound:  notFound,
	}

	printReport(report)

	return report
}

// Print a formatted report of the discovered directories
func printReport(report Report) {
	if len(report.FoundDirs) > 0 {
		color.Cyan("\n[*] Discovery completed. Directories found for %s:", report.Target)
		for _, dir := range report.FoundDirs {
			link := fmt.Sprintf("%s/%s", report.Target, dir)
			color.Green("- %s", link)
		}
	} else {
		color.Yellow("\n[-] Discovery completed. No directories found for %s.", report.Target)
	}

	if len(report.NotFound) > 0 {
		color.Yellow("\n[*] Directories not found for %s:", report.Target)
		for _, dir := range report.NotFound {
			color.Red("- %s", dir)
		}
	}
}
