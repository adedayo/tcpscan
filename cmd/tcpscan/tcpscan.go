package main

import (
	"fmt"
	"github.com/adedayo/tcpscan"
	"github.com/urfave/cli"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

var (
	version = "0.0.0" // deployed version will be taken from release tags
	commit  = "none"
	date    = "unknown"
)

func main() {

	app := cli.NewApp()
	app.Name = "tcpscan"
	app.Version = version
	app.Usage = "Scan for open TCP ports on servers"
	app.UsageText = `Scan for open (or closed) TCP ports on servers. 
	
Example:
	
tcpscan 8.8.8.8/32 10.10.10.1/30

`
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "json, j",
			Usage: "generate JSON output",
		},
	}
	app.EnableBashCompletion = true

	app.Authors = []cli.Author{
		{
			Name:  "Adedayo Adetoye (Dayo)",
			Email: "https://github.com/adedayo",
		},
	}

	app.Action = func(c *cli.Context) error {
		return process(c)
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}

func process(c *cli.Context) error {
	if c.NArg() == 0 {
		c.App.Run([]string{"tcpscan", "h"})
		return nil
	}
	args := []string{}
	args = append(args, c.Args().First())
	args = append(args, c.Args().Tail()...)
	scan := make(map[string]portscan.PortACK)
	for ack := range portscan.ScanCIDR(args...) {
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

	if c.GlobalBool("json") {
		outputJSON(portAckList)
	} else {
		outputText(portAckList)
	}
	return nil
}

func outputJSON(ports []portscan.PortACK) {
	result := ""
	current := ""
	hostName := ""
	ind := 0
	for _, p := range ports {
		if p.Host != current {
			ind = 0
			if current != "" {
				result += `]},
  `
			}
			current = p.Host
			h, err := net.LookupAddr(p.Host)
			if err != nil {
				hostName = ""
			} else {
				hostName = fmt.Sprintf("%s", strings.Join(h, ", "))
			}
			result += fmt.Sprintf(
				`  "%s": 
     {
	   "resolved": "%s",
	   "ports": [
		  `, p.Host, hostName)

		}
		prefix := ""
		if ind != 0 {
			prefix = `,
	          `
		}
		result += fmt.Sprintf(`%s{"port": %s, "state": "%s","service": "%s"}`,
			prefix, p.Port, p.Status(), p.GetServiceName())
		ind++
	}
	println("{\n" + result + `]}
}`)
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
