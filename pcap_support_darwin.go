package portscan

import (
	"github.com/google/gopacket/pcap"
)

func closeHandle(handle *pcap.Handle, host string, config ScanConfig, stop chan bool) {
	handle.Close()
	stop <- true
}
