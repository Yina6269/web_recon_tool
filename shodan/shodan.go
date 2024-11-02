package shodan

import (
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"net"
	"net/http"
)

const baseURL = "https://api.shodan.io"

type ShodanHost struct {
	IPStr     string            `json:"ip_str"`
	Ports     []int             `json:"ports"`
	Vulns     map[string]string `json:"vulns"`
	ISP       string            `json:"isp"`
	Org       string            `json:"org"`
	Hostnames []string          `json:"hostnames"`
}

// FetchHostInfo queries the Shodan API to get host info for the target IP
func FetchHostInfo(apiKey, targetIP string) (*ShodanHost, error) {
	url := fmt.Sprintf("%s/shodan/host/%s?key=%s", baseURL, targetIP, apiKey)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("received non-200 response: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var hostInfo ShodanHost
	if err := json.Unmarshal(body, &hostInfo); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &hostInfo, nil
}

// DisplayHostInfo displays the Shodan information about the target IP
func DisplayHostInfo(hostInfo *ShodanHost) {
	color.Cyan("\nShodan Report for IP: %s", hostInfo.IPStr)
	color.Cyan("ISP: %s | Organization: %s", hostInfo.ISP, hostInfo.Org)
	color.Cyan("Hostnames: %v\n", hostInfo.Hostnames)

	color.Cyan("Open Ports:")
	for _, port := range hostInfo.Ports {
		color.Green("  - Port %d is open", port)
	}

	color.Cyan("\nPotential Vulnerabilities:")
	if len(hostInfo.Vulns) > 0 {
		for vulnID, description := range hostInfo.Vulns {
			color.Red("  - %s: %s", vulnID, description)
		}
	} else {
		color.Yellow("  No vulnerabilities found.")
	}
}

// ResolveHostToIP resolves a domain name to an IP address
func ResolveHostToIP(target string) (string, error) {
	ips, err := net.LookupIP(target)
	if err != nil {
		return "", fmt.Errorf("could not resolve host: %v", err)
	}

	for _, ip := range ips {
		if ip.To4() != nil { // Return the first IPv4 address
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("no IPv4 address found for host")
}

// GetShodanInfo fetches and returns Shodan host information for the given target
func GetShodanInfo(apiKey, target string) (*ShodanHost, error) {
	targetIP, err := ResolveHostToIP(target)
	if err != nil {
		return nil, fmt.Errorf("error resolving host: %v", err)
	}

	hostInfo, err := FetchHostInfo(apiKey, targetIP)
	if err != nil {
		return nil, fmt.Errorf("error fetching data from Shodan: %v", err)
	}

	return hostInfo, nil
}
