package portscan

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

//PortACK describes a port with an ACK after a TCP SYN request
type PortACK struct {
	Host string
	Port string
	RST  bool
	SYN  bool
}

//IsClosed determines whether the port is filtered by e.g. by a firewall
func (p PortACK) IsClosed() bool {
	return p.RST && !p.SYN
}

//IsOpen determines whether the port is open or not
func (p PortACK) IsOpen() bool {
	return !p.RST || p.SYN
}

//Status is a string representation of the port status
func (p PortACK) Status() string {
	if p.IsOpen() {
		return "open"
	}
	if p.IsClosed() {
		return "closed"
	}
	return "unknown"
}

//GetServiceName returns the service name indicated by the port number
func (p PortACK) GetServiceName() string {
	if name, present := knownPortMap[p.Port]; present {
		return name
	}
	return "unknown"
}

//Piggybacking on NMap services list for common ports and frequency to determine the order of port scans. See: https://svn.nmap.org/nmap/nmap-services
//See processNMAPServices for how we extract the data. This is an internal API at the moment, used to generate the data in definitions.go. We are interested only in TCP ports at the moment
//processNMAPServices gets a sorted set of ports from the nmap-services file
func processNMAPServices() {
	file, err := os.Open("nmap-services.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	ports := []knownPort{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		data := strings.Split(line, "\t")
		if len(data) < 3 {
			continue
		}
		freq := float64(0)
		if f, err := strconv.ParseFloat(data[2], 64); err == nil {
			freq = f
		}
		if strings.HasSuffix(data[1], "/tcp") {
			//interesting line
			ports = append(ports, knownPort{
				Name:      data[0],
				ID:        strings.Split(data[1], "/")[0],
				Frequency: freq,
			})
		}
	}

	sort.Sort(knownPortSorter(ports))

	out, err := os.Create("services.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	out2, err := os.Create("ports-only.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer out2.Close()

	for _, p := range ports {
		fmt.Printf("%#v\n", p)

		port, err := strconv.Atoi(p.ID)
		if err != nil {
			panic(err)
		}
		//write in a format that can be easily copied into a map[string]string {...}
		out.WriteString(fmt.Sprintf("`%s`: `%s`,\n", p.ID, p.Name))
		//write in a format that can be easily copied into an []int {...}
		out2.WriteString(fmt.Sprintf("%d,", port))
	}
}

//knownPort is a struct for NMAP known ports dataset
type knownPort struct {
	ID        string
	Name      string
	Frequency float64
}

type knownPortSorter []knownPort

func (k knownPortSorter) Len() int {
	return len(k)
}

func (k knownPortSorter) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}
func (k knownPortSorter) Less(i, j int) bool {
	return k[i].Frequency > k[j].Frequency //sort descending
}
