package portscan

import (
	"os"
	"runtime/pprof"

	"github.com/google/gopacket/pcap"
)

func closeHandle(handle *pcap.Handle) {
	pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
	handle.Close()

	println("After close")
	pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
}
