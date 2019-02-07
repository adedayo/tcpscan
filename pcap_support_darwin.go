package portscan

import (
	"github.com/google/gopacket/pcap"
)

func closeHandle(handle *pcap.Handle, host string, config ScanConfig) {
	handle.Close()
}
