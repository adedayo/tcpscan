package portscan

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackpal/gateway"

	"github.com/adedayo/cidr"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/ratelimit"
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

	lastConfig ScanConfig
	lastRoute  routeFinder
)

type routeFinder struct {
	IsPPP           bool
	SrcHardwareAddr net.HardwareAddr
	DstHardwareAddr net.HardwareAddr
	SrcIP           net.IP
	Device          pcap.Interface
	Interface       net.Interface
}

//ScanCIDR scans for open TCP ports in IP addresses within a CIDR range
func ScanCIDR(config ScanConfig, cidrAddresses ...string) <-chan PortACK {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Error: %+v\n", r)
			os.Exit(1)
		}
	}()
	rate := 1000
	if config.PacketsPerSecond > 0 {
		rate = config.PacketsPerSecond
	} else {
		panic(fmt.Errorf("Invalid packets per second: %d. Stopping", config.PacketsPerSecond))
	}
	rl := ratelimit.New(rate) //ratelimit number of packets per second
	route := getRoute(config)
	cidrPortMap := make(map[string][]int)
	for _, cidrX := range cidrAddresses {
		ports := []int{}
		if strings.Contains(cidrX, ":") {
			cidrPorts := strings.Split(cidrX, ":")
			cRange := ""
			if strings.Contains(cidrX, "/") {
				cRange = "/" + strings.Split(cidrX, "/")[1]
			}
			cidrX = cidrPorts[0] + cRange
			ports = parsePorts(strings.Split(cidrPorts[1], "/")[0])
		}
		cidrX = getNet(cidrX)
		if len(ports) == 0 {
			ports = knownPorts[:]
		}
		if currentPorts, present := cidrPortMap[cidrX]; !present {
			cidrPortMap[cidrX] = ports
		} else {
			cidrPortMap[cidrX] = append(currentPorts, ports...)
		}
	}
	cidrXs := []string{}
	for cidrX := range cidrPortMap {
		cidrXs = append(cidrXs, "net "+cidrX)
	}

	//restrict filtering to the specified CIDR IPs and listen for inbound ACK packets
	filter := fmt.Sprintf(`(%s) and not src host %s`, strings.Join(cidrXs, " or "), route.SrcIP.String())
	handle := getHandle(filter, config)
	out := listenForACKPackets(handle, route, config)

	go func() {
		for cidrX, cidrPorts := range cidrPortMap {
			ipAdds := cidr.Expand(cidrX)
			//shuffle the IP addresses pseudo-randomly
			mathrand.Shuffle(len(ipAdds), func(i, j int) {
				ipAdds[i], ipAdds[j] = ipAdds[j], ipAdds[i]
			})

			count := 1 //Number of SYN packets to send per port (make this a parameter)
			//Send SYN packets asynchronously
			go func(ips []string, ports []int) { // run the scans in parallel
				writeHandle := getHandle(filter, config)
				stopPort := 65535
				sourcePort := 50000
				for _, dstPort := range ports {
					for _, dstIP := range ips {
						dst := net.ParseIP(dstIP)
						// Send a specified number of SYN packets
						for i := 0; i < count; i++ {
							rl.Take()
							// fmt.Printf("Sending to IP %s and port %d\n", dstIP, dstPort)
							err := sendSYNPacket(route.SrcIP, dst, sourcePort, dstPort, route, writeHandle)
							bailout(err)
							sourcePort++
							if sourcePort > stopPort {
								sourcePort = 50000
							}
						}
					}
				}
				writeHandle.Close()
			}(ipAdds, cidrPorts)
		}
		timeout := time.Duration(config.Timeout) * time.Second
		select {
		case <-time.After(timeout):
			closeHandle(handle)
		}
	}()
	return out
}

//a hopefully more performant route finder that doesnt re-do the work
func getRoute(config ScanConfig) routeFinder {
	//use precomputed
	if config == lastConfig {
		return lastRoute
	}
	//get the network interface to use for scanning: ppp0, eth0, en0 etc.
	route := routeFinder{}
	dev, netIface, err := getPreferredDevice(config)
	bailout(err)
	route.Device = dev
	route.Interface = netIface
	iface, err := getIPv4InterfaceAddress(dev)
	bailout(err)
	route.SrcIP = iface.IP
	if strings.HasPrefix(dev.Name, "ppp") {
		route.IsPPP = true
	} else {
		routerHW, err := determineRouterHardwareAddress(config)
		bailout(err)
		route.SrcHardwareAddr = netIface.HardwareAddr
		route.DstHardwareAddr = routerHW
	}
	lastConfig = config
	lastRoute = route
	return route
}

func parsePorts(portsString string) (ports []int) {
	pp := strings.Split(portsString, ",")
	for _, p := range pp {
		if strings.Contains(p, "-") {
			ps := strings.Split(p, "-")

			if len(ps) != 2 {
				continue
			}
			i, err := strconv.Atoi(ps[0])
			if err != nil {
				continue
			}
			j, err := strconv.Atoi(ps[1])
			if err != nil {
				continue
			}

			if j < i {
				i, j = j, i
			}
			for index := i; index < j; index++ {
				ports = append(ports, index)
			}

		} else {
			i, err := strconv.Atoi(p)
			if err != nil {
				continue
			}
			ports = append(ports, i)
		}
	}
	return
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
	// fmt.Printf("%#v", firstLayer)
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
	outAlt := alternativeGatewayHWDiscovery(config)
	google := "www.google.com"
	_, iface, err := getPreferredDevice(config)
	bailout(err)
	handle := getTimedHandle(fmt.Sprintf("host %s and ether dst %s", google, iface.HardwareAddr.String()), 5*time.Second, config)
	out := listenForEthernetPackets(handle)
	go func() {
		_, err = net.DialTimeout("tcp", fmt.Sprintf("%s:443", google), 5*time.Second)
		bailout(err)
	}()
	select {
	case hwAddress := <-out: //found via TCP connect
		return hwAddress, nil
	case hwAddress := <-outAlt: //found via ARP
		return hwAddress, nil
	case <-time.After(30 * time.Second):
		return nil, errors.New("Timeout error: could not determine the router hardware address in time")
	}
}

func alternativeGatewayHWDiscovery(config ScanConfig) <-chan net.HardwareAddr {
	dev, iface, err := getPreferredDevice(config)
	bailout(err)
	var srcIP net.IP
	for _, add := range dev.Addresses {
		if !add.IP.IsLoopback() && add.IP.To4() != nil {
			srcIP = add.IP
			break
		}
	}
	dstIP, err := gateway.DiscoverGateway()
	if err != nil {
		bailout(err)
	}
	handle, err := pcap.OpenLive(dev.Name, 65536, true, 20*time.Second)
	if err != nil {
		bailout(err)
	}
	out := readARP(handle, &iface, dstIP)
	writeArp(handle, &iface, srcIP, dstIP)
	return out
}

func readARP(handle *pcap.Handle, iface *net.Interface, dstIP []byte) <-chan net.HardwareAddr {
	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	output := make(chan net.HardwareAddr)
	targetIP := net.IP(dstIP)
	go func() {
		for packet := range packetSource.Packets() {
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp := arpLayer.(*layers.ARP)
				if srcIP := net.IP(arp.SourceProtAddress); arp != nil && srcIP.Equal(targetIP) {
					out := net.HardwareAddr(arp.SourceHwAddress)
					output <- out
				}
			}
		}
		close(output)
	}()
	return output
}

func writeArp(handle *pcap.Handle, srcIFace *net.Interface, srcIP, dstIP net.IP) {
	eth := layers.Ethernet{
		SrcMAC:       srcIFace.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		Operation:         layers.ARPRequest,
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		SourceHwAddress:   []byte(srcIFace.HardwareAddr),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP),
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, options, &eth, &arp)
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		bailout(err)
	}
}

//listenForEthernetPackets collects packets on the network that meet port scan specifications
func listenForEthernetPackets(handle *pcap.Handle) <-chan net.HardwareAddr {
	output := make(chan net.HardwareAddr)
	go func() {
		var eth layers.Ethernet
		// var ip layers.IPv4
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth)
		// parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip)
		decodedLayers := []gopacket.LayerType{}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			// fmt.Printf("Packet: %#v\n", packet)
			parser.DecodeLayers(packet.Data(), &decodedLayers)
			for _, lyr := range decodedLayers {
				//Look for Ethernet frames
				// fmt.Printf("Decoded: %#v\n", lyr)
				if lyr.Contains(layers.LayerTypeEthernet) {
					// println("Mac: ", eth.SrcMAC)
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
func listenForACKPackets(handle *pcap.Handle, route routeFinder, config ScanConfig) <-chan PortACK {
	output := make(chan PortACK)
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

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		for {
			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				break
			}
			if err != nil {
				if err.Error() == pcap.NextErrorTimeoutExpired.Error() {
					continue
				}
			}
			parser.DecodeLayers(packet.Data(), &decodedLayers)
			for _, lyr := range decodedLayers {
				//Look for TCP ACK
				if lyr.Contains(layers.LayerTypeTCP) {
					ack := PortACK{
						Host: ip.SrcIP.String(),
						Port: strings.Split(tcp.SrcPort.String(), "(")[0],
						SYN:  tcp.SYN,
						RST:  tcp.RST,
					}
					output <- ack
					if !config.Quiet && ack.IsOpen() {
						fmt.Printf("%s:%s (%s) is %s\n", ack.Host, ack.Port, ack.GetServiceName(), ack.Status())
					}
					break
				}
			}
		}
		close(output)
	}()
	return output
}

func bailout(err error) {
	if err != nil {
		panic(err.Error())

	}
}

func getPreferredDevice(config ScanConfig) (pcap.Interface, net.Interface, error) {
	if config == lastConfig { //shortcut if we've already obtained the device
		return lastRoute.Device, lastRoute.Interface, nil
	}

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
	typeNames := []string{"b", "c", "o", "s", "p", "x", "v", "a"}
	for _, iface := range interfaces {
		for _, tn := range typeNames {
			for _, i := range []int{0, 1, 2, 3} { //only try the first four possible index numbers
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
