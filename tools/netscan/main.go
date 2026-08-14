// netscan is a drop-in, faster replacement for Get-NetworkAsset's port-scan
// loop (DCAnomalyAgent/Modules/DCAnomalyAgent.Discovery.psm1). It exists
// because PowerShell's ForEach-Object -Parallel has real limitations for this
// workload: -ArgumentList isn't usable with -Parallel, module-scope functions
// don't cross the runspace boundary (hence the duplicated _port scriptblock in
// both branches of the PS version), and its parallelism is thread-pool based
// with meaningful per-runspace overhead - all real bugs and inefficiencies
// this codebase already hit once. Go's goroutines + net.DialTimeout have none
// of that: one process, real concurrency, a static binary with no runtime to
// install.
//
// Output is a JSON array on stdout with the exact same field names
// Get-NetworkAsset produces (Name, IP, AssetType, OpenPorts, Source,
// LastSeen), so Run-Discovery.ps1 can pipe the result straight into
// ConvertFrom-Json and use it exactly as before. If this binary isn't present
// on a given server, Run-Discovery.ps1 falls back to the PowerShell
// implementation automatically - this is an optional accelerator, not a hard
// dependency.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type asset struct {
	Name      string `json:"Name"`
	IP        string `json:"IP"`
	AssetType string `json:"AssetType"`
	OpenPorts string `json:"OpenPorts"`
	Source    string `json:"Source"`
	LastSeen  string `json:"LastSeen"`
}

func defaultPorts() map[string]int {
	return map[string]int{
		"SMB": 445, "WinRM": 5985, "RPC": 135, "SSH": 22, "LDAP": 389,
		"Kerberos": 88, "SNMP": 161, "Telnet": 23, "HTTPS": 443,
	}
}

// parsePorts parses "Name=Port,Name=Port,..." - the same shape
// Discovery.ScanPorts is passed through as from PowerShell/settings.psd1.
func parsePorts(spec string) (map[string]int, error) {
	if strings.TrimSpace(spec) == "" {
		return defaultPorts(), nil
	}
	ports := map[string]int{}
	for _, pair := range strings.Split(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid -ports entry %q, expected Name=Port", pair)
		}
		port, err := strconv.Atoi(strings.TrimSpace(kv[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid port number in %q: %w", pair, err)
		}
		ports[strings.TrimSpace(kv[0])] = port
	}
	if len(ports) == 0 {
		return defaultPorts(), nil
	}
	return ports, nil
}

// expandTarget mirrors Expand-Cidr in DCAnomalyAgent.Discovery.psm1: accepts a
// CIDR (10.0.0.0/24), a bare IPv4 (treated as /32), or a hostname (resolved to
// its current IPv4 address(es) at scan time - the same DNS-based approach
// used for laptops that roam VLANs/DHCP leases).
func expandTarget(target string) ([]string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, nil
	}

	if !strings.Contains(target, "/") {
		if ip := net.ParseIP(target); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				return []string{v4.String()}, nil
			}
			return nil, fmt.Errorf("only IPv4 is supported: %s", target)
		}
		// Not an IP literal - looked like digits-only but didn't parse as an
		// IP means a malformed CIDR/IP attempt, not a hostname.
		if len(target) > 0 && (target[0] >= '0' && target[0] <= '9') {
			return nil, fmt.Errorf("invalid CIDR or IP: %s", target)
		}
		addrs, err := net.LookupHost(target)
		if err != nil {
			return nil, fmt.Errorf("could not resolve hostname %q: %w", target, err)
		}
		var v4s []string
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil {
				if v4 := ip.To4(); v4 != nil {
					v4s = append(v4s, v4.String())
				}
			}
		}
		if len(v4s) == 0 {
			return nil, fmt.Errorf("hostname %q resolved to no IPv4 address", target)
		}
		return v4s, nil
	}

	_, ipnet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %s", target)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only IPv4 CIDRs are supported: %s", target)
	}
	if ones < 16 {
		return nil, fmt.Errorf("CIDR %s is larger than the supported /16-/32 range", target)
	}

	var ips []string
	base := ipnet.IP.To4()
	baseInt := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	hostBits := 32 - ones
	count := uint32(1) << uint(hostBits)
	for i := uint32(0); i < count; i++ {
		n := baseInt + i
		ip := net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func probePort(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func classify(ports map[string]bool) string {
	isWin := ports["SMB"] || ports["WinRM"] || ports["RPC"]
	switch {
	case ports["LDAP"] && ports["Kerberos"] && isWin:
		return "DomainController"
	case isWin:
		return "Windows"
	case ports["SSH"]:
		return "Linux"
	case ports["SNMP"] || ports["Telnet"]:
		return "NetworkDevice"
	default:
		return "Unknown"
	}
}

func scanHost(ip string, scanPorts map[string]int, timeout time.Duration, source string) *asset {
	open := map[string]bool{}
	anyOpen := false
	for name, port := range scanPorts {
		if probePort(ip, port, timeout) {
			open[name] = true
			anyOpen = true
		}
	}
	if !anyOpen {
		return nil
	}

	var names []string
	for name := range open {
		names = append(names, name)
	}
	sort.Strings(names)

	name := ip
	if hostnames, err := net.LookupAddr(ip); err == nil && len(hostnames) > 0 {
		name = strings.TrimSuffix(hostnames[0], ".")
	}

	return &asset{
		Name:      name,
		IP:        ip,
		AssetType: classify(open),
		OpenPorts: strings.Join(names, ","),
		Source:    source,
		LastSeen:  time.Now().UTC().Format("2006-01-02T15:04:05.0000000Z"),
	}
}

func main() {
	cidrFlag := flag.String("cidr", "", "Comma-separated CIDR ranges, IPs, and/or hostnames to scan (required)")
	portsFlag := flag.String("ports", "", "Comma-separated Name=Port pairs to probe (default: the standard 9-port classification set)")
	timeoutMs := flag.Int("timeout-ms", 700, "Per-port connect timeout in milliseconds")
	concurrency := flag.Int("concurrency", 512, "Max concurrent host probes")
	source := flag.String("source", "NetworkScan", "Value to stamp into the Source field (e.g. 'Cloudflare WARP')")
	flag.Parse()

	if strings.TrimSpace(*cidrFlag) == "" {
		fmt.Fprintln(os.Stderr, "netscan: -cidr is required")
		os.Exit(2)
	}

	scanPorts, err := parsePorts(*portsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netscan: %v\n", err)
		os.Exit(2)
	}

	seen := map[string]bool{}
	var ips []string
	for _, target := range strings.Split(*cidrFlag, ",") {
		expanded, err := expandTarget(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "netscan: %v\n", err)
			os.Exit(1)
		}
		for _, ip := range expanded {
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}

	timeout := time.Duration(*timeoutMs) * time.Millisecond
	sem := make(chan struct{}, *concurrency)
	results := make(chan *asset, len(ips))
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if a := scanHost(ip, scanPorts, timeout, *source); a != nil {
				results <- a
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var assets []asset
	for a := range results {
		assets = append(assets, *a)
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].IP < assets[j].IP })
	if assets == nil {
		assets = []asset{}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(assets); err != nil {
		fmt.Fprintf(os.Stderr, "netscan: failed to encode output: %v\n", err)
		os.Exit(1)
	}
}
