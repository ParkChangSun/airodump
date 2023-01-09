package main

import (
	"fmt"

	"github.com/airodump/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	handler, err := pcap.OpenLive("mon0", 1600, true, pcap.BlockForever)
	utils.PanicError(err)

	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Printf("packet: %v\n", packet)
	}
}
