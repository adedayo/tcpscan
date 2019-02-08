package portscan

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/pcap"
)

func closeHandle(handle *pcap.Handle, connectHost string, config ScanConfig) {
	println("closing handle", connectHost)
	go handle.Close()
	println("closing handle 2", connectHost)

	go func() {
		//dial an arbitrary port to generate packet to ensure the handle closes - some weirdness on Linux versions using TPACKET_V3
		//see https://github.com/tsg/gopacket/pull/15 and https://github.com/elastic/beats/issues/6535
		println("sending packet to ", connectHost)

		net.DialTimeout("tcp", fmt.Sprintf("%s:443", connectHost), time.Second)

		println("XXX sent packet to ", connectHost)

	}()
}
