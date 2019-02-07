package portscan

import (
	"github.com/google/gopacket/pcap"
)

func closeHandle(handle *pcap.Handle, config ScanConfig) {
	handle.Close()
}

func getHandle(bpfFilter string, config ScanConfig) *pcap.Handle {
	dev, _, err := getPreferredDevice(config)
	bailout(err)
	handle, err := pcap.OpenLive(dev.Name, 65535, false, pcap.BlockForever)
	bailout(err)
	handle.SetBPFFilter(bpfFilter)
	return handle
}

//CommandLineExit - exit hack for Linux command line
func CommandLineExit(config ScanConfig) {
	//do noting on darwin
}
