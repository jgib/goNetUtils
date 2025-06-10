package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
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

type DnsHeader struct {
	id      uint16 // assigne by program generating query
	qr      byte   // 1 bit; Query/Response; 0 = query, 1 = response
	opcode  byte   // 4 bit; 0 = QUERY, 1 = IQUERY, 2 = STATUS, 3-15 = future use
	aa      byte   // 1 bit; Authoritative Answer
	tc      byte   // 1 bit; Truncation
	rd      byte   // 1 bit; Recursion Desired
	ra      byte   // 1 bit; Recursion Available
	z       byte   // 3 bit; future use; must be 0
	rcode   byte   //4 bit; Response Code; 0 = No error, 1 = Format error, 2 = Server failure, 3 = Name error, 4 = Not implemented, 5 = Refused, 6-15 = future use
	qdcount uint16 // Number of entries in question section
	ancount uint16 // Number of resource records in answer section
	nscount uint16 // Number of server resource records in the authority records section
	arcount uint16 // Number of resource records in additional records section
}

type DnsQuestion struct {
	qname  []byte // domain name represented as a sequence of labels, where each label consists of a length octet followed by that number of octets, terminates with the zero length octet for the null label of the root
	qtype  uint16 // type of query
	qclass uint16 // class of the query
}

type DnsResourceRecord struct {
	name     []byte
	rrType   uint16
	class    uint16
	TTL      uint32
	rdLength uint16
	rData    []byte
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

	fmt.Printf("Reply Datagram: %X\n", tmp3)
	fmt.Println(util.WalkByteSlice(tmp3))

	fmt.Println(tmp2)

	fmt.Println("Test DNS")

	var tmpHeader DnsHeader
	var tmpQuestion []DnsQuestion

	tmpHeader.id = 42069
	tmpHeader.opcode = 0
	tmpHeader.tc = 0
	tmpHeader.rd = 1
	tmpHeader.z = 0
	tmpHeader.rcode = 0
	tmpHeader.qdcount = 1
	tmpHeader.ancount = 0
	tmpHeader.nscount = 0
	tmpHeader.arcount = 0

	var tmpQ DnsQuestion
	tmpQ.qname = append(tmpQ.qname, 5)
	tmpQ.qname = append(tmpQ.qname, []byte("yahoo")...)
	tmpQ.qname = append(tmpQ.qname, 3)
	tmpQ.qname = append(tmpQ.qname, []byte("com")...)
	tmpQ.qname = append(tmpQ.qname, 0)
	tmpQuestion = append(tmpQuestion, tmpQ)

	tmp4, err := DnsGenerateDatagram(tmpHeader, tmpQuestion, nil)
	util.Er(err)
	fmt.Println(util.WalkByteSlice(tmp4))

	fmt.Println("DNS Reply")
	tmp5, err := DnsQuery(tmp4, "8.8.8.8", 53, "UDP")
	util.Er(err)
	fmt.Println(util.WalkByteSlice(tmp5))

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

func Ping(datagram []byte, dest string, timeout time.Duration) ([]byte, error) {
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

	_, err = conn.Write(datagram)
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

func DnsGenerateDatagram(header DnsHeader, questions []DnsQuestion, resourceRecords []DnsResourceRecord) ([]byte, error) {
	var datagram []byte

	if header.z != 0 {
		return nil, fmt.Errorf("invalid header value for z [%d], must be zero", header.z)
	}

	datagram = append(datagram, byte(header.id>>8), byte(header.id))
	datagram = append(datagram, byte(header.qr&1))
	datagram = append(datagram, byte(header.opcode&15))
	datagram = append(datagram, byte(header.aa&1))
	datagram = append(datagram, byte(header.tc&1))
	datagram = append(datagram, byte(header.rd&1))
	datagram = append(datagram, byte(header.ra&1))
	datagram = append(datagram, byte(header.z&7))
	datagram = append(datagram, byte(header.rcode&15))
	datagram = append(datagram, byte(header.qdcount>>8))
	datagram = append(datagram, byte(header.qdcount))
	datagram = append(datagram, byte(header.ancount>>8))
	datagram = append(datagram, byte(header.ancount))
	datagram = append(datagram, byte(header.nscount>>8))
	datagram = append(datagram, byte(header.nscount))
	datagram = append(datagram, byte(header.arcount>>8))
	datagram = append(datagram, byte(header.arcount))

	for i := 0; i < len(questions); i++ {
		datagram = append(datagram, questions[i].qname...)
		datagram = append(datagram, byte(questions[i].qtype>>8))
		datagram = append(datagram, byte(questions[i].qtype))
		datagram = append(datagram, byte(questions[i].qclass>>8))
		datagram = append(datagram, byte(questions[i].qclass))
	}

	for i := 0; i < len(resourceRecords); i++ {
		datagram = append(datagram, resourceRecords[i].name...)
		datagram = append(datagram, byte(resourceRecords[i].rrType>>8))
		datagram = append(datagram, byte(resourceRecords[i].rrType))
		datagram = append(datagram, byte(resourceRecords[i].class>>8))
		datagram = append(datagram, byte(resourceRecords[i].class))
		datagram = append(datagram, byte(resourceRecords[i].TTL>>24))
		datagram = append(datagram, byte(resourceRecords[i].TTL>>16))
		datagram = append(datagram, byte(resourceRecords[i].TTL>>8))
		datagram = append(datagram, byte(resourceRecords[i].TTL))
		datagram = append(datagram, byte(resourceRecords[i].rdLength>>8))
		datagram = append(datagram, byte(resourceRecords[i].rdLength))
		datagram = append(datagram, resourceRecords[i].rData...)
	}

	return datagram, nil
}

func DnsQuery(datagram []byte, dest string, port uint16, proto string) ([]byte, error) {
	if strings.ToUpper(proto) != "UDP" && strings.ToUpper(proto) != "TCP" {
		return nil, fmt.Errorf("invalid protocol specified [%s]", proto)
	}

	if strings.ToUpper(proto) == "UDP" {
		addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", dest, port))
		if err != nil {
			return nil, err
		}
		conn, err := net.DialUDP("udp4", nil, addr)
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		_, err = conn.Write(datagram)
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

	return nil, nil
}
