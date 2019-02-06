package portscan

import (
	"time"

	"github.com/google/gopacket/pcap"
)

func closeHandle(handle *pcap.Handle) {
	// //do nothing :-(
	// pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
	handle.Close()
	// println("After close")
	// pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
}

func getHandle(bpfFilter string, config ScanConfig) *pcap.Handle {
	dev, _, err := getPreferredDevice(config)
	bailout(err)
	handle, err := pcap.OpenLive(dev.Name, 65535, false, 480*time.Hour) //some arbitrarily long time
	bailout(err)
	handle.SetBPFFilter(bpfFilter)
	return handle
}
