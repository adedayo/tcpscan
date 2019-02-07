package portscan

import (
	"github.com/google/gopacket/pcap"
)

func getHandle(bpfFilter string, config ScanConfig) *pcap.Handle {
	dev, _, err := getPreferredDevice(config)
	bailout(err)
	handle, err := pcap.OpenLive(dev.Name, 65535, false, pcap.BlockForever)
	bailout(err)
	handle.SetBPFFilter(bpfFilter)
	return handle
}

func closeHandle(handle *pcap.Handle, config ScanConfig) {
	// //do nothing :-(
	// pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)

	handle.Close()

	// println("After close")
	// pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
}
