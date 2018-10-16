package portscan

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/adedayo/cidr"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	options = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	tcpOptions = []layers.TCPOption{
		layers.TCPOption{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{0x5, 0xb4}, //1460
		},
		layers.TCPOption{
			OptionType: layers.TCPOptionKindNop,
		},
		layers.TCPOption{
			OptionType:   layers.TCPOptionKindWindowScale,
			OptionLength: 3,
			OptionData:   []byte{0x5},
		},
		layers.TCPOption{
			OptionType: layers.TCPOptionKindNop,
		},
		layers.TCPOption{
			OptionType: layers.TCPOptionKindNop,
		},
		layers.TCPOption{
			OptionType:   layers.TCPOptionKindTimestamps,
			OptionLength: 10,
			OptionData:   []byte{0xac, 0x49, 0x31, 0xcb, 0x0, 0x0, 0x0, 0x0},
		},
		layers.TCPOption{
			OptionType:   layers.TCPOptionKindSACKPermitted,
			OptionLength: 2,
		},
		layers.TCPOption{
			OptionType: layers.TCPOptionKindEndList,
		},
	}
)

type routeFinder struct {
	IsPPP           bool
	SrcHardwareAddr net.HardwareAddr
	DstHardwareAddr net.HardwareAddr
}

//ScanCIDR scans for open TCP ports in IP addresses within a CIDR range
func ScanCIDR(config ScanConfig, cidrAddresses ...string) <-chan PortACK {
	out := make(chan PortACK)
	go func() {
		defer close(out)
		//get the network interface to use for scanning: ppp0, eth0, en0 etc.
		dev, netIface, err := getPreferredDevice(config)
		bailout(err)
		route := routeFinder{}
		iface, err := getIPv4InterfaceAddress(dev)
		bailout(err)
		src := iface.IP
		if strings.HasPrefix(dev.Name, "ppp") {
			route.IsPPP = true
		} else {
			routerHW, err := determineRouterHardwareAddress(config)
			bailout(err)
			route.SrcHardwareAddr = netIface.HardwareAddr
			route.DstHardwareAddr = routerHW
		}

		stoppers := []<-chan bool{}
		ipCount := 1
		timeout := time.Duration(config.Timeout) * time.Second
		for _, cidrX := range cidrAddresses {
			ips := cidr.Expand(cidrX)
			ipCount += len(ips)
			//restrict filtering to the specified CIDR IPs and listen for inbound ACK packets
			filter := fmt.Sprintf(`net %s and not src host %s`, getNet(cidrX), src.String())
			handle := getTimedHandle(filter, timeout, config)
			stopper := listenForACKPackets(filter, route, timeout, out, config)
			stoppers = append(stoppers, stopper)
			count := 1 //Number of SYN packets to send per port (make this a parameter)
			//Send SYN packets asynchronously
			go func() { // run the scans in parallel
				stopPort := 65535
				sourcePort := 50000
				for _, dstIP := range ips {
					dst := net.ParseIP(dstIP)
					for _, dstPort := range knownPorts {
						// Send a specified number of SYN packets
						for i := 0; i < count; i++ {
							err = sendSYNPacket(src, dst, sourcePort, dstPort, route, handle)
							bailout(err)
							sourcePort++
							if sourcePort > stopPort {
								sourcePort = 50000
							}
						}
					}
				}
			}()
		}
		// wait for a factor of the total number of IPs and ports
		delay := time.Duration(ipCount*len(knownPorts)/50) * time.Millisecond
		time.Sleep(delay)

		for range merge(stoppers...) {
			//wait for the completion or timeouts
		}
	}()
	return out
}

//allow domains to be used in CIDRs
func getNet(cidrX string) (result string) {
	adds := strings.Split(cidrX, "/")
	rng := "/32"
	if strings.Contains(cidrX, "/") {
		rng = "/" + adds[1]
	}
	ips, err := net.LookupIP(adds[0])
	if err != nil {
		return
	}
	return ips[0].String() + rng
}

func merge(stoppers ...<-chan bool) <-chan bool {
	var wg sync.WaitGroup
	out := make(chan bool)
	output := func(c <-chan bool) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(stoppers))
	for _, c := range stoppers {
		go output(c)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func sendSYNPacket(src, dst net.IP, srcPort, dstPrt int, route routeFinder, handle *pcap.Handle) error {
	var firstLayer gopacket.SerializableLayer
	if route.IsPPP {
		ppp := layers.PPP{
			PPPType: layers.PPPTypeIPv4,
		}
		ppp.Contents = []byte{0xff, 0x03}
		firstLayer = &ppp
	} else {
		eth := layers.Ethernet{
			SrcMAC:       route.SrcHardwareAddr,
			DstMAC:       route.DstHardwareAddr,
			EthernetType: layers.EthernetTypeIPv4,
		}
		firstLayer = &eth
	}
	ip4 := layers.IPv4{
		SrcIP:      src,
		DstIP:      dst,
		Version:    4,
		TOS:        0,
		Id:         0,
		Flags:      layers.IPv4Flag(2),
		FragOffset: 0,
		TTL:        255,
		Protocol:   layers.IPProtocolTCP,
	}

	timebuf := make([]byte, 8)
	rand.Read(timebuf)
	for i := 4; i < 8; i++ {
		timebuf[i] = 0x0
	}
	tcpOptions[5] = layers.TCPOption{
		OptionType:   layers.TCPOptionKindTimestamps,
		OptionLength: 10,
		OptionData:   timebuf,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPrt),
		SYN:     true, // we'd like to send a SYN packet
		Window:  65535,
		Options: tcpOptions,
	}

	tcp.SetNetworkLayerForChecksum(&ip4)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, options, firstLayer, &ip4, &tcp); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())

}

//determineRouterHardwareAddress finds the router by looking at the ethernet frames that returns the TCP ACK handshake from "google"
func determineRouterHardwareAddress(config ScanConfig) (net.HardwareAddr, error) {
	google := "www.google.com"
	_, iface, err := getPreferredDevice(config)
	bailout(err)
	handle := getTimedHandle(fmt.Sprintf("host %s and ether dst %s", google, iface.HardwareAddr.String()), 5*time.Second, config)
	out := listenForEthernetPackets(handle)
	_, _ = net.Dial("tcp", fmt.Sprintf("%s:443", google))
	select {
	case hwAddress := <-out:
		return hwAddress, nil
	case <-time.After(5 * time.Second):
		return nil, errors.New("Timeout error: could not determine the router hardware address in time")
	}
}

//listenForEthernetPackets collects packets on the network that meet port scan specifications
func listenForEthernetPackets(handle *pcap.Handle) <-chan net.HardwareAddr {
	output := make(chan net.HardwareAddr)
	go func() {
		var eth layers.Ethernet
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth)
		decodedLayers := []gopacket.LayerType{}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			parser.DecodeLayers(packet.Data(), &decodedLayers)
			for _, lyr := range decodedLayers {
				//Look for Ethernet frames
				if lyr.Contains(layers.LayerTypeEthernet) {
					output <- eth.SrcMAC
					break
				}
			}
		}
		close(output)
	}()
	return output
}

// MyPPP is layers.PPP with CanDecode and other decoding operations implemented
type MyPPP layers.PPP

//CanDecode indicates that we can decode PPP packets
func (ppp *MyPPP) CanDecode() gopacket.LayerClass {
	return layers.LayerTypePPP
}

//LayerType -
func (ppp *MyPPP) LayerType() gopacket.LayerType { return layers.LayerTypePPP }

//DecodeFromBytes as name suggest
func (ppp *MyPPP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) > 2 && data[0] == 0xff && data[1] == 0x03 {
		ppp.PPPType = layers.PPPType(binary.BigEndian.Uint16(data[2:4]))
		ppp.Contents = data
		ppp.Payload = data[4:]
		return nil
	}
	return errors.New("Not a PPP packet")
}

//NextLayerType gets type
func (ppp *MyPPP) NextLayerType() gopacket.LayerType {
	return layers.LayerTypeIPv4
}

//listenForACKPackets collects packets on the network that meet port scan specifications
func listenForACKPackets(filter string, route routeFinder, timeout time.Duration, output chan<- PortACK, config ScanConfig) chan bool {
	done := make(chan bool)
	var ip layers.IPv4
	var tcp layers.TCP
	var parser *gopacket.DecodingLayerParser
	if route.IsPPP {
		var ppp MyPPP
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypePPP, &ppp, &ip, &tcp)
	} else {
		var eth layers.Ethernet
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip, &tcp)
	}

	decodedLayers := []gopacket.LayerType{}
	handle := getTimedHandle(filter, timeout, config)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		// for packet := range packetSource.Packets() {
		for {
			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				break
			}
			if err != nil {
				if err.Error() == pcap.NextErrorTimeoutExpired.Error() {
					continue
				} else {
					//some other error, will be useful for debugging
					// println(err.Error())
				}
			}

			parser.DecodeLayers(packet.Data(), &decodedLayers)
			for _, lyr := range decodedLayers {
				//Look for TCP ACK
				if lyr.Contains(layers.LayerTypeTCP) {
					if tcp.ACK {
						output <- PortACK{
							Host: ip.SrcIP.String(),
							Port: strings.Split(tcp.SrcPort.String(), "(")[0],
							SYN:  tcp.SYN,
							RST:  tcp.RST,
						}
						break
					}
				}
			}
		}
		close(done)
	}()

	//stop after timeout
	go func() {
		select {
		case <-time.After(timeout):
			handle.Close()
		}
	}()
	return done
}

func bailout(err error) {
	if err != nil {
		panic(err.Error())
	}
}

func getPreferredDevice(config ScanConfig) (pcap.Interface, net.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return pcap.Interface{}, net.Interface{}, err
	}

	if config.Interface != "" {
		ifx, err := net.InterfaceByName(config.Interface)
		if err != nil {
			return pcap.Interface{}, net.Interface{}, err
		}
		dev := pcap.Interface{}
		for _, d := range devices {
			if d.Name == config.Interface {
				dev = d
				break
			}
		}
		return dev, *ifx, err
	}

	for i := 0; i < 5; i++ {
		//search in this order: VPN, then non-VPN; from lower interface index 0 up till 4
		//i.e ppp0, en0, eth0, ppp1, en1, eth1, ...
		for _, iface := range []string{"ppp", "en", "eth"} {
			for _, dev := range devices {
				if dev.Name == fmt.Sprintf("%s%d", iface, i) {
					ifx, err := getRoutableInterface(dev)
					return dev, ifx, err
				}
			}
		}
	}

	// try guessing based on systemd's predictable network interface naming heuristics
	// see https://github.com/systemd/systemd/blob/master/src/udev/udev-builtin-net_id.c
	// note that this is a simple algorithm, not rigorous
	interfaces := []string{"en", "ib", "sl", "wl", "ww"}
	typeNames := []string{"b", "c", "o", "s", "x", "v", "a"}
	for _, iface := range interfaces {
		for _, tn := range typeNames {
			for _, i := range []int{0, 1} { //only try the first two possible index numbers
				for _, dev := range devices {
					if strings.HasPrefix(dev.Name, fmt.Sprintf("%s%s", iface, tn)) &&
						strings.HasSuffix(dev.Name, fmt.Sprintf("%d", i)) {
						ifx, err := getRoutableInterface(dev)
						if err != nil {
							continue
						}
						return dev, ifx, err
					}
				}
			}
		}
	}
	// try any interface with an IPv4 address
	for _, dev := range devices {
		ifx, err := getRoutableInterface(dev)
		if err != nil {
			continue
		}
		return dev, ifx, err
	}
	// give up and bail out
	return pcap.Interface{}, net.Interface{}, errors.New("Could not find a preferred interface with a routable IP")
}

func getRoutableInterface(dev pcap.Interface) (net.Interface, error) {
	if strings.HasPrefix(dev.Name, "ppp") {
		return net.Interface{}, nil
	}

	for _, add := range dev.Addresses {
		if !add.IP.IsLoopback() && strings.Contains(add.IP.String(), ".") {
			iface, err := net.InterfaceByName(dev.Name)
			if err != nil {
				return net.Interface{}, err
			}
			return *iface, nil
		}
	}
	return net.Interface{}, errors.New("No routable interface")
}

func getIPv4InterfaceAddress(iface pcap.Interface) (pcap.InterfaceAddress, error) {
	for _, add := range iface.Addresses {
		if strings.Contains(add.IP.String(), ".") {
			return add, nil
		}
	}
	return pcap.InterfaceAddress{}, errors.New("Could not find an interface with IPv4 address")
}

func getTimedHandle(bpfFilter string, timeOut time.Duration, config ScanConfig) *pcap.Handle {
	dev, _, err := getPreferredDevice(config)
	bailout(err)
	handle, err := pcap.OpenLive(dev.Name, 65535, false, timeOut)
	bailout(err)
	handle.SetBPFFilter(bpfFilter)
	return handle
}
