package main

import (
	"fmt"
	"net"
	"regexp"
	"time"

	util "github.com/jgib/utils"
)

type IcmpDatagram struct {
	// add RFC 6918
	originalDataDatagram   uint64
	originateTimestamp     uint32
	receiveTimestamp       uint32
	transmitTimestamp      uint32
	gatewayInternetAddress uint32
	sequenceNumber         uint16
	identifier             uint16
	pointer                uint16
	icmpType               byte
	code                   byte
	internetHeader         []byte
	data                   []byte
}

func main() {
	fmt.Println("Test")
	util.Debug("Test2", true)

	tmp := InetCksum([]byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xcb, 0x70, 0x44, 0x68, 0x00, 0x00, 0x00, 0x00, 0x15, 0xa4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37})
	fmt.Printf("%X\n", tmp)

	var icmpTmp IcmpDatagram
	icmpTmp.icmpType = 8
	icmpTmp.code = 0
	icmpTmp.identifier = 1
	icmpTmp.sequenceNumber = 1

	tmp2, err := IcmpGenerateDatagram(icmpTmp)
	util.Er(err)
	tmp3, err := Ping(tmp2, "8.8.8.8", time.Second*3)
	util.Er(err)

	util.WalkByteSlice(tmp3)

	fmt.Println(tmp2)

	util.Er(fmt.Errorf("ERROR TEST"))

}

func InetCksum(msg []byte) [2]byte {
	var tmp uint32

	// pad message to an even number of bytes
	if len(msg)%2 != 0 {
		msg = append(msg, 0)
	}

	for i := 0; i < len(msg); i++ {
		if i%2 != 0 {
			tmp += (uint32(msg[i-1]))<<8 + uint32(msg[i])
			tmp = (tmp & 0xFFFF) + (tmp >> 16)
		}
	}

	var cksum [2]byte
	cksum[0] = byte(tmp >> 8)
	cksum[1] = byte(tmp)
	cksum[0] = cksum[0] ^ 0xFF
	cksum[1] = cksum[1] ^ 0xFF

	return cksum
}

func Ping(input []byte, dest string, timeout time.Duration) ([]byte, error) {
	pattern := regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	if !pattern.MatchString(dest) {
		return nil, fmt.Errorf("invalid destination IPv4 address [%s]", dest)
	}

	conn, err := net.Dial("ip4:1", dest)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(input)
	if err != nil {
		return nil, err
	}

	replyDatagram := make([]byte, 65507)

	replySize, err := conn.Read(replyDatagram)
	if err != nil {
		return nil, err
	}

	return replyDatagram[:replySize], nil
}

func IcmpGenerateDatagram(input IcmpDatagram) ([]byte, error) {
	var datagram []byte

	datagram = append(datagram, byte(input.icmpType), byte(input.code), 0, 0)

	switch input.icmpType {
	case 0:
		datagram = append(datagram, byte(input.identifier>>8), byte(input.identifier), byte(input.sequenceNumber>>8), byte(input.sequenceNumber))
		datagram = append(datagram, input.data...)
	case 3, 11:
		datagram = append(datagram, 0, 0, 0, 0)
		datagram = append(datagram, input.internetHeader...)
		datagram = append(datagram, byte(input.originalDataDatagram>>56), byte(input.originalDataDatagram>>48), byte(input.originalDataDatagram>>40),
			byte(input.originalDataDatagram>>32), byte(input.originalDataDatagram>>24), byte(input.originalDataDatagram>>16),
			byte(input.originalDataDatagram>>8), byte(input.originalDataDatagram))
	case 4: // depercated
	case 5:
		datagram = append(datagram, byte(input.gatewayInternetAddress>>24), byte(input.gatewayInternetAddress>>16), byte(input.gatewayInternetAddress>>8),
			byte(input.gatewayInternetAddress))
	case 6: // need to research
	case 8:
		datagram = append(datagram, byte(input.identifier>>8), byte(input.identifier), byte(input.sequenceNumber>>8), byte(input.sequenceNumber))
		datagram = append(datagram, input.data...)
	case 12:
		datagram = append(datagram, byte(input.pointer>>8), byte(input.pointer), 0, 0, 0)
		datagram = append(datagram, byte(input.originalDataDatagram>>56), byte(input.originalDataDatagram>>48), byte(input.originalDataDatagram>>40),
			byte(input.originalDataDatagram>>32), byte(input.originalDataDatagram>>24), byte(input.originalDataDatagram>>16),
			byte(input.originalDataDatagram>>8), byte(input.originalDataDatagram))
	case 13, 14:
		datagram = append(datagram, byte(input.identifier>>8), byte(input.identifier), byte(input.sequenceNumber>>8), byte(input.sequenceNumber))
		datagram = append(datagram, byte(input.originateTimestamp>>24), byte(input.originateTimestamp>>16), byte(input.originateTimestamp>>8),
			byte(input.originateTimestamp))
		datagram = append(datagram, byte(input.receiveTimestamp>>24), byte(input.receiveTimestamp>>16), byte(input.receiveTimestamp>>8),
			byte(input.receiveTimestamp))
		datagram = append(datagram, byte(input.transmitTimestamp>>24), byte(input.transmitTimestamp>>16), byte(input.transmitTimestamp>>8),
			byte(input.transmitTimestamp))
	case 15: // depercated
	default:
		return nil, fmt.Errorf("invalid type [%d] used", input.icmpType)
	}

	cksum := InetCksum(datagram)
	datagram[2] = cksum[0]
	datagram[3] = cksum[1]

	return datagram, nil
}
