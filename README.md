[![Build Status](https://travis-ci.org/adedayo/tcpscan.svg?branch=master)](https://travis-ci.org/adedayo/tcpscan)

# TCPScan 
TCPScan is a simple utility for discovering open (or closed) TCP ports on servers. It uses `gopacket`(https://github.com/google/gopacket) to craft SYN packets, listening asynchronously for (SYN-)ACK or RST responses without completing the full TCP handshake. TCPScan uses goroutines for asynchronous scans and it searches for the most likely listening ports first, using NMap's "port frequency" ordering. Anecdotal results show that TCPScan is really fast!

TCPScan is not a replacement for the awesome NMap tool, but it promises to be a useful library for go applications that need a fast and simple TCP port scanning capability.

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
	result := portscan.ScanCIDR(cidr)
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

## An issue on macOS
You may encounter errors such as 
```bash
panic: en0: You don't have permission to capture on that device ((cannot open BPF device) /dev/bpf0: Permission denied)
```
Fix the permission problem permanently by using the "Wireshark" approach of pre-allocating _/dev/bpf*_, and changing their permissions so that the _admin_ group can read from and write packets to the devices. Follow the steps below:


```bash
curl -O https://raw.githubusercontent.com/adedayo/tcpscan/master/com.github.adedayo.libpcap.bpf-helper.sh
curl -O https://raw.githubusercontent.com/adedayo/tcpscan/master/com.github.adedayo.libpcap.bpf-helper.plist

sudo su
mv com.github.adedayo.libpcap.bpf-helper.sh /Library/PrivilegedHelperTools/
mv com.github.adedayo.libpcap.bpf-helper.plist /Library/LaunchDaemons/
chown root:wheel /Library/PrivilegedHelperTools/com.github.adedayo.libpcap.bpf-helper.sh
chown root:wheel /Library/LaunchDaemons/com.github.adedayo.libpcap.bpf-helper.plist
chmod 755 /Library/PrivilegedHelperTools/com.github.adedayo.libpcap.bpf-helper.sh
launchctl load -w /Library/LaunchDaemons/com.github.adedayo.libpcap.bpf-helper.plist
```

You should be good to go! This works across reboots. Note that this is a common problem for tools such as Wireshark, TCPDump etc. that need to read from or write to /dev/bpf*. This solution should fix the problem for all of them - the idea was actually stolen from Wireshark with some modifications :-).

## License
BSD 3-Clause License