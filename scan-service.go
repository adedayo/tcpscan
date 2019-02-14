package portscan

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/adedayo/cidr"
	"github.com/carlescere/scheduler"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
)

var (
	//TCPScanConfigPath is the default config path of the TCPScan service
	TCPScanConfigPath = filepath.Join("data", "config", "TCPScanConfig.yml")
	tcpScanPath       = filepath.Join("data", "tcpscan", "scan")
	//control files
	runFlag     = filepath.Join("data", "tcpscan", "runlock.txt")
	runFlag2    = filepath.Join("data", "tcpscan", "deletethistoresume.txt")
	workList    = filepath.Join("data", "tcpscan", "worklist.txt")
	progress    = filepath.Join("data", "tcpscan", "progress.txt")
	resolvedIPs = make(map[string]string)
	ipLock      = sync.RWMutex{}
)

//Service main service entry function
func Service(configPath string) {
	println("Running TCPScan Service ...")
	TCPScanConfigPath = configPath
	ScheduleTCPScan(getIPsFromConfig)
	runtime.Goexit()
}

func getIPsFromConfig() []string {
	config, err := loadConfig(TCPScanConfigPath)
	if err != nil {
		return []string{}
	}
	ips := getIPsToScan(config)
	return ips
}

func getIPsToScan(config TCPScanConfig) []string {
	data := make(map[string]string)
	ips := []string{}
	for _, c := range config.CIDRRanges {
		ports := ""
		if strings.Contains(c, ":") {
			cc, p, err := extractPorts(c)
			if err != nil {
				continue
			}
			c = cc
			ports = p
		}
		for _, ip := range cidr.Expand(c) {
			ip = fmt.Sprintf("%s/32", ip)
			if ps, present := data[ip]; present {
				if ps == "" {
					data[ip] = ports
				} else if ports != "" {
					data[ip] = fmt.Sprintf("%s,%s", ps, ports)
				}
			} else {
				data[ip] = ports
			}
		}
	}
	for ip, ports := range data {
		x := ip

		if ports != "" {
			z := strings.Split(ip, "/")
			if len(z) != 2 {
				continue
			}
			x = fmt.Sprintf("%s:%s/%s", z[0], ports, z[1])
			println(x)
		}
		ips = append(ips, x)
	}
	return ips
}

func extractPorts(cidrX string) (string, string, error) {
	cs := strings.Split(cidrX, ":")
	if len(cs) != 2 {
		return cidrX, "", fmt.Errorf("Bad CIDR with port format %s", cidrX)
	}
	ip := cs[0]
	if !strings.Contains(cs[1], "/") {
		return ip + "/32", cs[1], nil
	}
	rng := strings.Split(cs[1], "/")
	if len(rng) != 2 {
		return cidrX, "", fmt.Errorf("Bad CIDR with port format %s", cidrX)
	}
	return fmt.Sprintf("%s/%s", ip, rng[1]), rng[0], nil
}

//ScheduleTCPScan runs TCPScan service scan
func ScheduleTCPScan(ipSource func() []string) {

	//a restart schould clear the lock file
	if _, err := os.Stat(runFlag2); !os.IsNotExist(err) { // there is a runlock
		if err := os.Remove(runFlag2); err != nil {
			println(err.Error())
			log.Error(err)
		}
	}

	scanJob := func() {
		runTCPScan(ipSource)
	}

	if config, err := loadConfig(TCPScanConfigPath); err == nil {
		for _, t := range config.DailySchedules {
			if config.IsProduction {
				println("Running next at ", t)
				scheduler.Every().Day().At(t).Run(scanJob)
			} else {
				scheduler.Every(2).Hours().Run(scanJob)
			}
		}
		//run a scan immediately if there is a previous incomplete scan
		if _, err := os.Stat(workList); !os.IsNotExist(err) {
			runTCPScan(ipSource)
		}
	}
}

func loadConfig(path string) (config TCPScanConfig, e error) {
	configFile, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error(err)
		return config, err
	}
	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		log.Error(err)
		return config, err
	}
	return
}

//runTCPScan accepts generator of IP addresses to scan and a function to map the IPs to hostnames (if any) - function to allow the hostname resolution happen in parallel if necessary
func runTCPScan(ipSource func() []string) {
	//create a directory, if not exist, for tlsaudit to keep temporary file
	path := tcpScanPath
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err2 := os.MkdirAll(path, 0755); err2 != nil {
			log.Errorln("Could not create the path ", path)
		}
	}

	//prevent concurrent runs
	if _, err := os.Stat(runFlag2); !os.IsNotExist(err) { // there is a runlock
		//do not start a new scan
		return
	}
	psr := PersistedScanRequest{}

	hosts := []string{}
	if _, err := os.Stat(workList); !os.IsNotExist(err) { // there is a worklist (due to a previous crash!)
		//load the list of IPs from there
		println("Resuming due to a worklist")
		file, err := os.Open(workList)
		if err != nil {
			log.Error(err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			hosts = append(hosts, scanner.Text())
		}

		day, err := ioutil.ReadFile(runFlag)
		if err != nil {
			log.Error(err)
			return
		}
		d := strings.TrimSpace(string(day))
		println("Resuming on date ", d, filepath.Join(path, d))
		dirs, err := ioutil.ReadDir(filepath.Join(path, d))
		if err != nil {
			println(err.Error())
			log.Error(err)
			return
		}
		fmt.Printf("%#v\n", dirs)
		for _, sID := range dirs {
			scanID := sID.Name()
			println(scanID)
			if p, err := LoadScanRequest(d, scanID); err == nil {
				psr = p
				break
			}
		}
		fmt.Printf("Will be scanning with PSR %#v", psr)
	} else { // starting a fresh scan
		hosts = ipSource()
		//shuffle hosts randomly
		rand.Shuffle(len(hosts), func(i, j int) {
			hosts[i], hosts[j] = hosts[j], hosts[i]
		})

		//write shuffled hosts into worklist file
		if err := ioutil.WriteFile(workList, []byte(strings.Join(hosts, "\n")+"\n"), 0644); err != nil {
			log.Error(err)
			return
		}

		//track progress in the progress file
		if err := ioutil.WriteFile(progress, []byte(fmt.Sprintf("-1,%d", len(hosts))), 0644); err != nil {
			log.Error(err)
			return
		}

		//create the lock file with the start day
		today := time.Now().Format(dayFormat)
		if err := ioutil.WriteFile(runFlag, []byte(today), 0644); err != nil {
			log.Error(err)
			return
		}

		if err := ioutil.WriteFile(runFlag2, []byte{}, 0644); err != nil {
			log.Error(err)
			return
		}
		psr.Hosts = hosts
		request := ScanRequest{}
		request.Day = today
		request.ScanID = GetNextScanID()
		config, _ := loadConfig(TCPScanConfigPath)
		scanConfig := ScanConfig{
			PacketsPerSecond: config.PacketsPerSecond,
			Timeout:          config.Timeout,
		}
		request.Config = scanConfig
		psr.Request = request
	}

	//get ready to scan
	//get where we "stopped" last time possibly after a crash
	stopped := 0
	p, err := ioutil.ReadFile(progress)
	if err != nil {
		log.Error(err)
		return
	}
	stopped, err = strconv.Atoi(strings.Split(string(p), ",")[0])
	if err != nil {
		log.Error(err)
		return
	}
	psr.Progress = stopped

	PersistScanRequest(psr)

	count := len(hosts)

	//scan hosts
	for index, host := range hosts {
		//skip already scanned hosts, if any
		if index <= stopped {
			fmt.Printf("Skipping host %s\n", host)
			continue
		}
		counter := index + 1
		scan := make(map[string]PortACK)
		results := []<-chan PortACK{}
		scanResults := []PortACK{}
		fmt.Printf("Scanning Host %s (%d of %d)\n", host, counter, count)
		results = append(results, ScanCIDR(psr.Request.Config, host))
		for result := range mergePortAckChannels(results...) {
			key := result.Host + result.Port
			if _, present := scan[key]; !present {
				scan[key] = result
				scanResults = append(scanResults, result)
				fmt.Printf("Got result for Host: %-16s Port: %-6s Status: %-7s Service: %s\n", result.Host, result.Port, result.Status(), result.GetServiceName())
			}
		}
		sort.Sort(PortAckSorter(scanResults))
		PersistScans(psr, host, scanResults)

		if err := ioutil.WriteFile(progress, []byte(fmt.Sprintf("%d,%d", counter, len(hosts))), 0644); err != nil {
			log.Error(err)
			return
		}

		psr.Progress = counter
		PersistScanRequest(psr)
	}

	//cleanup
	if err := os.Remove(runFlag); err != nil {
		log.Error(err)
	}
	if err := os.Remove(runFlag2); err != nil {
		log.Error(err)
	}
	if err := os.Remove(progress); err != nil {
		log.Error(err)
	}
	if err := os.Remove(workList); err != nil {
		log.Error(err)
	}
}

func mergePortAckChannels(channels ...<-chan PortACK) <-chan PortACK {
	var wg sync.WaitGroup
	out := make(chan PortACK)
	output := func(c <-chan PortACK) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(channels))
	for _, c := range channels {
		go output(c)
	}

	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}
