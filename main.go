package main

import (
	"os"
	"time"

	"github.com/airodump/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var channel_num_max = 14

func main() {
	ifSelect := os.Args[1]
	go hopChannel(ifSelect)

	dumpChan := make(chan utils.DumpRow)
	go utils.PrintDump(dumpChan)

	handler, err := pcap.OpenLive(ifSelect, 1600, true, pcap.BlockForever)
	utils.PanicError(err)

	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range packetSource.Packets() {
		handlePacket(packet, dumpChan)
	}
}

func hopChannel(iwInterface string) {
	currentChannel := 1
	for {
		time.Sleep(time.Millisecond * 10)
		err := utils.IwModChannel(iwInterface, currentChannel)
		utils.PanicError(err)

		currentChannel = (currentChannel % channel_num_max) + 1
	}
}

func handlePacket(packet gopacket.Packet, c chan utils.DumpRow) {
	if dotLayer := packet.Layer(layers.LayerTypeDot11MgmtBeacon); dotLayer != nil {
		newRow := utils.DumpRow{}

		rawDot11 := packet.Layer(layers.LayerTypeDot11).LayerContents()
		newRow.BSSId = utils.BytesToMac(rawDot11[16:22])

		newRow.Power = int(packet.Layer(layers.LayerTypeRadioTap).LayerContents()[22]) - 256

		for _, l := range packet.Layers() {
			if l.LayerType() == layers.LayerTypeDot11InformationElement {
				rawCont := l.LayerContents()

				if rawCont[0] == 0x00 {
					d := &layers.Dot11InformationElement{}
					d.DecodeFromBytes(rawCont, gopacket.NilDecodeFeedback)
					newRow.ESSId = string(d.Info)
				} else if rawCont[0] == 0x03 {
					newRow.Channel = int(rawCont[2])
				} else if rawCont[0] == 0x30 {
					// RSN information
					if rawCont[7] == 0x04 {
						newRow.Cipher = "CCMP"
					} else {
						newRow.Cipher = "specific"
					}
				}
			}
		}
		c <- newRow
	}
}
