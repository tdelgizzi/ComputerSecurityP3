/*
EECS 388 Project 3
Part 2. Anomaly Detection

detector.go
When completed (by you!) and compiled, this program will:
- Open a .pcap file supplied as a command-line argument, and analyze
the TCP, IP, Ethernet, and ARP layers.
- Print the IP addresses that: 1) sent more than 3 times as many SYN packets
as the number of SYN+ACK packets they received, and 2) sent more than 5 SYN
packets in total.
- Print the MAC addresses that send more than 5 unsolicited ARP replies.

This starter code is provided solely for convenience, to help
build familiarity with Go. You are free to use as much or as
little of this code as you see fit.
*/
package main

import (
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type senAck struct {
	Sent int
	Ack  int
}

func main() {
	if len(os.Args) != 2 {
		panic("Invalid command-line arguments")
	}
	pcapFile := os.Args[1]

	// Attempt to open file
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Loop through packets in file
	// Recommendation: Encapsulate packet handling and/or output in separate functions!
	//whoops ^

	var rqs = make(map[string][]string)
	var spoofs = make(map[string]int)

	//tcp
	var hsts = make(map[string]*senAck)

	for packet := range packetSource.Packets() {
		el := packet.Layer(layers.LayerTypeEthernet)
		al := packet.Layer(layers.LayerTypeARP)
		il := packet.Layer(layers.LayerTypeIPv4)
		tl := packet.Layer(layers.LayerTypeTCP)

		validARP := el != nil && al != nil
		validTCP := el != nil && il != nil && tl != nil

		// If the packet doesn't appear to be a valid ARP or TCP packet,
		// skip it.
		if !(validARP || validTCP) {
			continue
		}

		// Extract the actual information from the Ethernet layer.
		// See the definition of layers.Ethernet for more information.
		// (The ethernet layer is valid for both ARP and TCP packets.)

		//eth := el.(*layers.Ethernet)

		//layers.ethrnet

		switch {
		case validARP:
			// Extract the information from the ARP layer.
			arp := al.(*layers.ARP)

			// TODO: handle ARP packet

			//set up vars
			macsrc := net.HardwareAddr(arp.SourceHwAddress).String()
			ipsrc := net.IP(arp.SourceProtAddress).String()
			macdst := net.HardwareAddr(arp.DstHwAddress).String()
			ipdst := net.IP(arp.DstProtAddress).String()

			if arp.Operation == 1 {

				if _, check := rqs[ipdst]; !check {

					x := []string{macsrc}
					rqs[ipdst] = x
					x = nil

				} else {

					curMac := rqs[ipdst]
					curMac = append(curMac, macsrc)
					rqs[ipdst] = curMac
					curMac = nil

				}

			}
			if arp.Operation == 2 {
				if pckar, test := rqs[ipsrc]; test {
					flag := true
					for i, mac := range pckar {
						if mac == macdst {

							if len(pckar) > 1 {

								pckar[i] = pckar[len(pckar)-1]
								pckar[len(pckar)-1] = ""
								rqs[ipsrc] = pckar[:len(pckar)-1]

							} else {

								delete(rqs, ipsrc)

							}

							flag = false
							break
						}
					}
					if flag {

						if _, x := spoofs[macsrc]; !x {
							spoofs[macsrc] = 1
						} else {
							spoofs[macsrc] += 1
						}

					}
				} else {
					if _, x := spoofs[macsrc]; !x {
						spoofs[macsrc] = 1
					} else {
						spoofs[macsrc] += 1
					}

				}
			}

		case validTCP:
			// Extract the information from the IP and TCP layers.
			ip := il.(*layers.IPv4)
			tcp := tl.(*layers.TCP)

			// TODO: handle TCP packet
			ipsrc := ip.SrcIP.String()
			ipdst := ip.DstIP.String()

			if _, flip := hsts[ipsrc]; !flip {

				x := &senAck{0, 0}
				hsts[ipsrc] = x
				x = nil

			}

			if _, flip := hsts[ipdst]; !flip {

				x := &senAck{0, 0}
				hsts[ipdst] = x
				x = nil

			}

			if tcp.ACK && tcp.SYN {

				hsts[ipdst].Ack++

			} else if !tcp.ACK && tcp.SYN {

				hsts[ipsrc].Sent++

			}

		}
	}

	fmt.Println("Unauthorized SYN scanners:")
	// TODO: print SYN scanners

	for key, x := range hsts {

		if x.Sent > 4 && (x.Sent > (3 * x.Ack)) {

			fmt.Println(key)

		}
	}

	fmt.Println("Unauthorized ARP spoofers:")
	// TODO: print ARP spoofers

	for key, x := range spoofs {

		if x > 4 {

			fmt.Println(key)

		}
	}
}

/*
Hints and Links to Documentation:

Here are some links to useful pages of gopacket documentation, or
source code of layer objects in gopacket. The names of the
struct member variables are self-explanatory.

https://github.com/google/gopacket/blob/master/layers/tcp.go Lines 20-35
https://github.com/google/gopacket/blob/master/layers/ip4.go Lines 43-59
https://github.com/google/gopacket/blob/master/layers/arp.go Lines 18-36
In arp.go, HwAddress is the MAC address, and
ProtAddress is the IP address in this case. Both are []byte variables.
*/
