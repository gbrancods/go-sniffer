package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {

	i := searchInterfaces()
	fmt.Println(i)
	fmt.Println("Insert the name of the interface")

	var in string
	fmt.Scan(&in)

	networkCapture(in)
}

func searchInterfaces() string {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println("Not Found Interfaces")
	}

	var d string
	for _, dev := range devices {
		d += fmt.Sprintf("%s\n", dev.Name)
	}

	return d
}

func networkCapture(name string) {

	handle, err := pcap.OpenLive(name, 1600, false, pcap.BlockForever)

	if err != nil {
		fmt.Println("Error")
	}

	defer handle.Close()

	if err := handle.SetBPFFilter("tcp and port 443"); err != nil {
		fmt.Println(err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())

	for packets := range src.Packets() {
		fmt.Println(packets)
	}
}
