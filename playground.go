package main

import (
	"fmt"
	//"strings"
	"IVS/tlsrelay"
	"encoding/hex"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	//"github.com/google/gopacket/layers"
)
func main() {
	
	if handle, err := pcap.OpenLive("enx00e04c534458", 65535, true, pcap.BlockForever); err != nil {
		return
	} else {
		defer handle.Close()//move to end of function because of defer
		//source of packet
		
            //capture tcp or udp
		if err := handle.SetBPFFilter("tcp or udp"); err != nil {
			panic(err)
		}
            
		//handle.LinkType is type of link, ie: ethernet, sccp,...
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			//capture dn. Layer returns the first layer in this packet of type DNS
			host:=hex.EncodeToString(packet.TransportLayer().LayerContents()[:])
			fmt.Println(packet.TransportLayer().LayerType())
			fmt.Println(host)
		}
	}
}