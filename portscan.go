package portscan

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/adedayo/cidr"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"strings"
	"sync"
	"time"
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

//ScanCIDR scans for open TCP ports in IP addresses within a CIDR range
func ScanCIDR(cidrAddresses ...string) <-chan PortACK {
	out := make(chan PortACK)
	// cc := 0
	// for _, x := range cidrAddresses {
	// 	t := len(cidr.Expand(x))
	// 	cc += t
	// 	println(t, cc)
	// }
	// return nil
	go func() {
		// defer func() {
		// 	println("Closing Out")
		// 	close(out)
		// }()
		//get the network interface to use for scanning: eth0, en0 etc.
		dev, netIface, err := getPreferredDevice()
		bailout(err)
		iface, err := getIPv4InterfaceAddress(dev)
		bailout(err)
		src := iface.IP
		routerHW, err := determineRouterHardwareAddress()
		bailout(err)
		stoppers := []<-chan bool{}
		ipCount := 1
		for _, cidrX := range cidrAddresses {
			ips := cidr.Expand(cidrX)
			ipCount += len(ips)
			//restrict filtering to the specified CIDR IPs and listen for inbound ACK packets
			filter := fmt.Sprintf(`net %s and not src host %s`, cidrX, src.String())
			handle := getHandle(filter)
			// defer handle.Close()
			stopper := make(chan bool)
			stoppers = append(stoppers, stopper)
			go listenForACKPackets(stopper, out, handle)

			count := 1 //Number of SYN packets to send per port (make this a parameter)
			//Send SYN packets asynchronously
			go func() { // run the scans in parallel
				stopPort := 65535
				sourcePort := 50000
				for _, dstPort := range knownPorts {
					for _, dstIP := range ips {
						dst := net.ParseIP(dstIP)
						// Send a specified number of SYN packets
						for i := 0; i < count; i++ {
							err := sendSYNPacket(netIface.HardwareAddr, routerHW, src, dst, sourcePort, dstPort, handle)
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
		//wait for a factor of the total number of IPs and ports
		delay := time.Duration(ipCount*len(knownPorts)/50) * time.Millisecond
		// println("About to delay ", delay.String())
		time.Sleep(delay)
		counter := 0
		for _ = range merge(stoppers...) {
			counter++
			// println(cc, ipCount, counter, n)
		}
		close(out)
		// println("finished delay")
		// counter := 1
		// for _, st := range stoppers {
		// 	select {
		// 	case <-st:
		// 		println("A stopper is stopping")
		// 	}
		// 	// println("stopp2d count ", len(stoppers))
		// 	// counter++
		// }
		// time.Sleep(2000 * time.Millisecond)

	}()
	return out
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

func sendSYNPacket(srcMAC, dstMAC net.HardwareAddr, src, dst net.IP, srcPort, dstPrt int, handle *pcap.Handle) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
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
	// ipFlow := gopacket.NewFlow(layers.EndpointIPv4, dst, src)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, options, &eth, &ip4, &tcp); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())

}

//determineRouterHardwareAddress finds the router by looking at the ethernet frames that returns the TCP ACK handshake from "google"
func determineRouterHardwareAddress() (net.HardwareAddr, error) {
	google := "www.google.com"
	_, iface, err := getPreferredDevice()
	bailout(err)
	handle := getTimedHandle(fmt.Sprintf("host %s and ether dst %s", google, iface.HardwareAddr.String()), 5*time.Second)
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

//listenForACKPackets collects packets on the network that meet port scan specifications
func listenForACKPackets(done chan bool, output chan<- PortACK, handle *pcap.Handle) {

	// defer exiting("listen for packets")
	var eth layers.Ethernet
	var ip layers.IPv4
	var tcp layers.TCP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip, &tcp)
	decodedLayers := []gopacket.LayerType{}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		for packet := range packetSource.Packets() {
			// println("Packet", packet.String())
			// select {
			// case <-time.After(3 * time.Second):
			// 	println("Expired")
			// 	handle.Close()
			// 	return
			// case <-done:
			// 	println("DONE")
			// 	handle.Close()
			// 	return
			// default:
			// println("default")
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
			// }
		}
		// close(output)
	}()
	select {
	case <-time.After(2 * time.Second):
		println("Expired")
		handle.Close()
		done <- true
		close(done)
		return
	}

}

// func exiting(loc string) {
// 	println("Exiting location", loc)
// }

func bailout(err error) {
	if err != nil {
		// panic(err.Error())
		println("Error: ", err.Error())
	}
}

// func stringify(adds []pcap.InterfaceAddress) (result string) {
// 	for _, add := range adds {
// 		result += " " + add.IP.String()
// 	}
// 	return
// }
func getPreferredDevice() (pcap.Interface, net.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return pcap.Interface{}, net.Interface{}, err
	}

	// for _, dev := range devices {
	// 	iface, _ := net.InterfaceByName(dev.Name)
	// 	adds, _ := iface.Addrs()
	// 	println("device ", dev.Name, stringify(dev.Addresses), iface.HardwareAddr.String())
	// 	if len(adds) > 0 {
	// 		println(adds[0].String())
	// 	}
	// }
	for _, dev := range devices {
		// println("device ", dev.Name)
		if dev.Name == "en0" || dev.Name == "eth0" {

			if err != nil {
				return dev, net.Interface{}, err
			}
			iface, err := net.InterfaceByName(dev.Name)
			if err != nil {
				return dev, net.Interface{}, err
			}
			return dev, *iface, err
		}
	}

	//at this point no en0 or eth0 found. Attempt to use any first interface with a non-loopback IP :-S
	for _, dev := range devices {
		ip := dev.Addresses[0].IP
		if !ip.IsLoopback() {
			iface, err := net.InterfaceByName(dev.Name)
			if err != nil {
				return dev, net.Interface{}, err
			}
			return dev, *iface, err
		}
	}
	// give up and bail out
	return pcap.Interface{}, net.Interface{}, errors.New("Could not find a preferred interface with a routable IP")
}

func getIPv4InterfaceAddress(iface pcap.Interface) (pcap.InterfaceAddress, error) {

	for _, add := range iface.Addresses {
		if strings.Contains(add.IP.String(), ".") {
			return add, nil
		}
	}
	return pcap.InterfaceAddress{}, errors.New("Could not find an interface with IPv4 address")
}

func getHandle(bpfFilter string) *pcap.Handle {
	return getTimedHandle(bpfFilter, pcap.BlockForever)
}

func getTimedHandle(bpfFilter string, timeOut time.Duration) *pcap.Handle {
	dev, _, err := getPreferredDevice()
	bailout(err)
	addresses := []string{}
	for _, add := range dev.Addresses {
		addresses = append(addresses, fmt.Sprintf("dst host %s", add.IP.String()))
	}
	handle, err := pcap.OpenLive(dev.Name, 65535, false, timeOut)
	bailout(err)
	handle.SetBPFFilter(bpfFilter)
	return handle
}
