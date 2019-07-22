[![Build Status](https://travis-ci.org/adedayo/tcpscan.svg?branch=master)](https://travis-ci.org/adedayo/tcpscan)
[![Go Report Card](https://goreportcard.com/badge/github.com/adedayo/tcpscan)](https://goreportcard.com/report/github.com/adedayo/tcpscan)
![GitHub release](https://img.shields.io/github/release/adedayo/tcpscan.svg)
[![GitHub license](https://img.shields.io/github/license/adedayo/tcpscan.svg)](https://github.com/adedayo/tcpscan/blob/master/LICENSE)

# TCPScan 
TCPScan is a simple utility for discovering open (or closed) TCP ports on servers. It uses `gopacket`(https://github.com/google/gopacket) to craft SYN packets, listening asynchronously for (SYN-)ACK or RST responses without completing the full TCP handshake. TCPScan uses goroutines for asynchronous scans and it searches for the most likely listening ports first, using NMap's "port frequency" ordering. Anecdotal results show that TCPScan is fast!

TCPScan is not a replacement for the awesome NMap tool, but it promises to be a useful library for go applications that need a fast and simple TCP port scanning capability.

## Using it as a command-line tool
TCPScan is also available as a command-line tool. 

### Installation
Prebuilt binaries may be found for your operating system here: https://github.com/adedayo/tcpscan/releases

For macOS X, you could install via brew as follows:
```bash
brew tap adedayo/tap
brew install tcpscan
``` 

### Scanning CIDR ranges

```bash
tcpscan 192.168.2.5/30 10.11.12.13/31
```

For JSON-formatted output simply add the `--json` or `-j` flag:

```bash
tcpscan --json 192.168.2.5/30 10.11.12.13/31
```
Depending on the fidelity of the network being scanned or the size of CIDR ranges, it may be expedient to adjust the scan timeout accordingly with the `--timeout` or `-t` flag, which indicates the number of seconds to wait for ACK or RST responses as follows:

```bash
tcpscan --json --timeout 5 192.168.2.5/30 10.11.12.13/31
```

Note that scans generally run faster with shorter timeouts, but you may be sacrificing accuracy on slow networks or for large CIDR ranges.

### Command line options

```bash
Usage:
  tcpscan [flags]

Examples:
tcpscan 8.8.8.8/32 10.10.10.1/30

Flags:
  -h, --help                                               help for tcpscan
  -j, --json                                               generate JSON output
  -q, --quiet                                              control whether to produce a running commentary of intermediate results or stay quiet till the end
  -r, --rate int                                           the rate (in packets per second) that we should send SYN scan packets. This influences overall scan time, but be careful not to overwhelm your network (default 1000)
  -s, --service string[="data/config/TCPScanConfig.yml"]   run tcpscan as a service (default "data/config/TCPScanConfig.yml")
  -t, --timeout int                                        TIMEOUT (in seconds) to adjust how much we are willing to wait for servers to come back with responses. Smaller timeout sacrifices accuracy for speed (default 5)
      --version                                            version for tcpscan
```

## Using TCPScan as a library
In order to start, go get this repository:
```go
go get github.com/adedayo/tcpscan
```

### Example
In your code simply import as usual and enjoy:

```go
package main

import 
(
    "fmt"
    "github.com/adedayo/tcpscan"
)

func main() {
	cidr := "8.8.8.8/32"
	config := portscan.ScanConfig {
		Timeout: 5,
	}
	result := portscan.ScanCIDR(config, cidr)
	for ack := range result {
         fmt.Printf("%s:\tPort %s(%s) is %s\n", ack.Host, ack.Port, ack.GetServiceName(), status(ack))
    }
}

func status(ack portscan.PortACK) string {
	if ack.IsClosed() {
		return "Closed"
	}
	if ack.IsOpen() {
		return "Open"
	}
	return "of Unknown Status"
}

```
This should produce an output similar to the following:
```
8.8.8.8:        Port 80(http) is Open
8.8.8.8:        Port 21(ftp) is Open
8.8.8.8:        Port 143(imap) is Open
8.8.8.8:        Port 110(pop3) is Open
8.8.8.8:        Port 113(ident) is Closed
8.8.8.8:        Port 443(https) is Open
8.8.8.8:        Port 8008(http-alt) is Open
8.8.8.8:        Port 119(nntp) is Open
8.8.8.8:        Port 8010 is Open
```

## An issue on macOS
You may encounter errors such as 
```bash
panic: en0: You don't have permission to capture on that device ((cannot open BPF device) /dev/bpf0: Permission denied)
```
Fix the permission problem permanently by using the "Wireshark" approach of pre-allocating _/dev/bpf*_, and changing their permissions so that the _admin_ group can read from and write packets to the devices. I have provided the _fix-bpf-permissions.sh_ script to simplify the steps, you can run it as shown below. It will ask for your password for the privileged part of the script, but read the script to satisfy yourself that you trust what it is doing! You care about security, right?

```bash
curl -O https://raw.githubusercontent.com/adedayo/tcpscan/master/fix-bpf-permissions.sh
chmod +x fix-bpf-permissions.sh
./fix-bpf-permissions.sh  
```

You should be good to go! You may need to reboot once, but this works across reboots. Note that this is a common problem for tools such as Wireshark, TCPDump etc. that need to read from or write to /dev/bpf*. This solution should fix the problem for all of them - the idea was actually stolen from Wireshark with some modifications :-).

## Running as non-root on Linux
You ideally want to be able to run `tcpscan` as an ordinary user, say, `my_user`, but since `tcpscan` sends raw packets you need to adjust capabilities to allow it to do so. The following may be necessary:

Ensure the following two lines are in _/etc/security/capability.conf_
```bash
cap_net_admin   my_user
none *
```

Also, in _/etc/pam.d/login_ add the following 
```bash
auth    required        pam_cap.so
```

Finally, grant the capability to the `tcpscan` file (assuming _/path/to_ is the absolute path to your `tcpscan` binary)
```bash
setcap cap_net_raw,cap_net_admin=eip /path/to/tcpscan
```
## License
BSD 3-Clause License