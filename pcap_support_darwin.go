package portscan

import "github.com/google/gopacket/pcap"

func closeHandle(handle *pcap.Handle) {
	handle.Close()
}
