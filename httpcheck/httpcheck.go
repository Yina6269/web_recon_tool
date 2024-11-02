package httpcheck

import (
	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"net/http"
	"strings"
	"time"
)

// Display banner for HTTP response check
func displayBanner() {
	banner := figure.NewColorFigure("HTTP Response Checker", "straight", "blue", true)
	banner.Print()
}

// Check performs an HTTP GET request and prints status details with enhanced formatting.
func Check(url string) {
	displayBanner()

	// Ensure the URL starts with http:// or https://
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url // Default to http if no prefix is present
	}

	color.Cyan("Starting HTTP response check for: %s\n", url)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		color.Red("Error: Unable to reach %s\nDetails: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	color.Cyan("HTTP Status for %s: %s\n", url, resp.Status)

	// Display status category with color based on response code
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		color.Green("✓ Success: Status Code %d (%s)\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		color.Yellow("➜ Redirection: Status Code %d (%s)\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		color.Red("⚠ Client Error: Status Code %d (%s)\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	case resp.StatusCode >= 500:
		color.Magenta("✖ Server Error: Status Code %d (%s)\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	default:
		color.White("Unknown Status: Status Code %d (%s)\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
}
