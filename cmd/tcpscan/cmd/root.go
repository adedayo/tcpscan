// Copyright © 2019 Adedayo Adetoye (aka Dayo)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/adedayo/cidr"
	portscan "github.com/adedayo/tcpscan"
	"github.com/spf13/cobra"
)

var (
	cfgFile, iface, service string
	jsonOut, quiet          bool
	timeout, rate           int
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "tcpscan",
	Short:   "Scan for open TCP ports on servers",
	Example: "tcpscan 8.8.8.8/32 10.10.10.1/30",
	RunE:    runner,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) {
	rootCmd.Version = version
	rootCmd.Long = fmt.Sprintf(`Scan for open (or closed) TCP ports on servers. 
	
Version: %s

Author: Adedayo Adetoye (Dayo) <https://github.com/adedayo>`, version)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	configPath := "config/path"
	app := "tcpscan"
	rootCmd.Flags().BoolVarP(&jsonOut, "json", "j", false, "generate JSON output")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "control whether to produce a running commentary of intermediate results or stay quiet till the end")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 5, "TIMEOUT (in seconds) to adjust how much we are willing to wait for servers to come back with responses. Smaller timeout sacrifices accuracy for speed")
	rootCmd.Flags().IntVarP(&rate, "rate", "r", 1000, "the rate (in packets per second) that we should send SYN scan packets. This influences overall scan time, but be careful not to overwhelm your network")
	rootCmd.Flags().StringVarP(&service, "service", "s", configPath, fmt.Sprintf("run %s as a service", app))
	rootCmd.Flag("service").NoOptDefVal = configPath
}

func runner(cmd *cobra.Command, args []string) error {
	if len(args) == 0 && !cmd.Flag("service").Changed {
		return cmd.Usage()
	}

	if !jsonOut {
		fmt.Printf("Starting TCPScan %s (%s)\n", cmd.Version, "https://github.com/adedayo/tcpscan")
	}
	t := time.Now()
	scan := make(map[string]portscan.PortACK)
	config := portscan.ScanConfig{
		Timeout:          timeout,
		PacketsPerSecond: rate,
		Quiet:            quiet,
		Interface:        iface,
		CommandLine:      true,
	}
	for ack := range portscan.ScanCIDR(config, args...) {
		key := ack.Host + ack.Port
		if _, present := scan[key]; !present {
			scan[key] = ack
		}
	}

	var portAckList []portscan.PortACK
	for k := range scan {
		portAckList = append(portAckList, scan[k])
	}

	sort.Sort(portAckSorter(portAckList))

	if jsonOut {
		outputJSON(portAckList)
	} else {
		outputText(portAckList)
	}
	hosts := []string{}
	for _, h := range args {
		hosts = append(hosts, cidr.Expand(h)...)
	}
	fmt.Printf("Scanned %d hosts in %f seconds\n", len(hosts), time.Since(t).Seconds())
	return nil
}

func outputJSON(ports []portscan.PortACK) {
	hostnames := make(map[string][]string)
	results := make(map[string]jsonResult)
	for _, ack := range ports {
		ip := ack.Host
		if _, present := hostnames[ip]; !present {
			h, err := net.LookupAddr(ip)
			if err != nil {
				hostnames[ip] = []string{}
			} else {
				hostnames[ip] = h
			}
		}

		if res, present := results[ip]; !present {
			res = jsonResult{
				IP:        ip,
				Hostnames: hostnames[ip],
				Ports:     []portState{},
			}
			results[ip] = res
		}

		result := results[ip]
		if port, err := strconv.Atoi(ack.Port); err == nil {
			result.Ports = append(result.Ports, portState{
				Port:    port,
				Service: ack.GetServiceName(),
				State:   ack.Status(),
			})
			results[ip] = result
		}
	}
	data := []jsonResult{}
	for _, v := range results {
		data = append(data, v)
	}
	if out, err := json.MarshalIndent(data, "", "  "); err == nil {

		println(string(out))
	}
}

func outputText(ports []portscan.PortACK) {
	result := ""
	current := ""
	hostName := ""
	for _, p := range ports {
		if p.Host != current {
			current = p.Host
			h, err := net.LookupAddr(p.Host)
			if err != nil {
				hostName = ""
			} else {
				hostName = fmt.Sprintf("(%s)", strings.Join(h, ", "))
			}
			result += fmt.Sprintf("\nTCPScan result for %s %s\n", p.Host, hostName)
			result += fmt.Sprintf("%-6s %-10s %s\n", "PORT", "STATE", "SERVICE")
		}
		result += fmt.Sprintf("%-6s %-10s %s\n", p.Port, p.Status(), p.GetServiceName())
	}
	println(result)
}

func status(ack portscan.PortACK) string {
	if ack.IsClosed() {
		return "Closed"
	}
	if ack.IsOpen() {
		return "Open"
	}
	return "Unknown Status"
}

type portAckSorter []portscan.PortACK

func (k portAckSorter) Len() int {
	return len(k)
}

func (k portAckSorter) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}
func (k portAckSorter) Less(i, j int) bool {
	iPort, _ := strconv.Atoi(k[i].Port)
	jPort, _ := strconv.Atoi(k[j].Port)
	return k[i].Host < k[j].Host || (k[i].Host == k[j].Host && iPort <= jPort)
}

type jsonResult struct {
	IP        string
	Hostnames []string
	Ports     []portState
}

type portState struct {
	Port    int
	State   string
	Service string
}
