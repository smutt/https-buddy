package main

import "fmt"
import "log"
import "io"
import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"

func doStuff(){
	inactive, err := pcap.NewInactiveHandle("en0")
	if err != nil{
		log.Fatal(err)
	}
	defer inactive.CleanUp()

	err = inactive.SetImmediateMode(true)
	if err != nil{
		log.Fatal(err)
	}

	iFace, err := inactive.Activate()
	if err != nil{
		log.Fatal(err)
	}

	BPF_HELLO_4 := "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (dst port 443)"
	err = iFace.SetBPFFilter(BPF_HELLO_4)
	if err != nil{
		log.Fatal(err)
	}
	
	source := gopacket.NewPacketSource(iFace, iFace.LinkType())
	for{
		pkt, err := source.NextPacket()
		if err == io.EOF{
			break
		}else if err != nil{
			log.Println("Error:", err)
			continue
		}
		fmt.Printf("pkt:", pkt.String())

	}
}




func main() {
	fmt.Printf("Starting \n")
	doStuff()	
	fmt.Printf("Finished \n")
}
