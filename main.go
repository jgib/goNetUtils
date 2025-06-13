package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
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

type DhcpDatagram struct {
	op      byte      // 1=BOOTREQUEST, 2=BOOTREPLY
	htype   byte      // HW ADDR TYPE; 1=Ethernet (10Mb), etc, ... see "assigned Numbers" RFC
	hlen    byte      // 6 for 10mb ethernet
	hops    byte      // client sets to zero
	xid     uint32    // random number choosen by client
	secs    uint16    // seconds since client began address acquisition or renawal process
	flags   uint16    // flags
	ciaddr  uint32    // Client IP address; only filled if client is in BOUND, RENEW, or REBINDING state
	yiaddr  uint32    // 'your' (client) IP address
	siaddr  uint32    // IP address of next server (bootstrap)
	giaddr  uint32    // Relay agent IP address
	chaddr  [16]byte  // Client hardware address
	sname   [64]byte  // Optional server host name; null terminated string
	file    [128]byte // Boot file name, null terminated string
	options []byte    // Optional parameters field

	/*
	   First 4 octets of the options field contain the decimal values [99][130][83][99].  This is the same
	   magic cookie as defined in RFC 1497.

	   OPTION  DESCRIPTION
	   0       Pad [0]
	   1       Subnet Mask                     [1][len(4)][m1][m2][m3][m4]
	   2       Time Offset                     [2][len(4)][n1][n2][n3][n4]
	   3       Router Option                   [3][len(n)][a1][a2][a3][a4][a1][a2][...]
	   4       Time Server Option              [4][len(n)][a1][a2][a3][a4][a1][a2][...]
	   5       Name Server Option              [5][len(n)][a1][a2][a3][a4][a1][a2][...]
	   6       Domain Name Server Option       [6][len(n)][a1][a2][a3][a4][a1][a2][...]
	   7       Log Server Option               [7][len(n)][a1][a2][a3][a4][a1][a2][...]
	   8       Cookie Server Option            [8][len(n)][a1][a2][a3][a4][a1][a2][...]
	   9       LPR Server Option               [9][len(n)][a1][a2][a3][a4][a1][a2][...]
	   10      Impress Server Option           [10][len(n)][a1][a2][a3][a4][a1][a2][...]
	   11      Resource Location Server Option [11][len(n)][a1][a2][a3][a4][a1][a2][...]
	   12      Host Name Option                [12][len(n)][h1][h2][h3][h4][h5][h6][...]
	   13      Boot File Size Option           [13][len(2)][l1][l2]
	   14      Merit Dumpt File                [14][len(n)][n1][n2][n3][n4][...]
	   15      Domain Name                     [15][len(n)][d1][d2][d3][d4][...]
	   16      Swap Server                     [16][len(4)][a1][a2][a3][a4]
	   17      Root Path                       [17][len(n)][n1][n2][n3][n4][...]
	   18      Extensions Path                 [18][len(n)][n1][n2][n3][n4][...]
	   19      IP Forwarding Option            [19][len(1)][0|1]
	   20      Non-Local Source Routing Option [20][len(1)][0|1]
	   21      Policy Filter Option            [21][len(n)[a1][a2][a3][a4][m1][m2][m3][m4][a1][a2][a3][a4][m1][m2][m3][m4][...]
	   22      Max Datagram Reassembly Size    [22][len(2)][s1][s2]
	   23      Default IP Time-to-live         [23][len(1)][ttl]
	   24      Path MTU Aging Timout Option    [24][len(4)][t1][t2][t3][t4]
	   25      Path MTU Plateau Table Option   [25][len(n)][s1][s2][s1][s2][...]
	   26      Interface MTU Option            [26][lne(2)][m1][m2]
	   27      All Subnets are Local Option    [27][len(1)][0|1]
	   28      Broadcast Address Option        [28][len(4)][b1][b2][b3][b4]
	   29      Perform Mask Discovery Option   [29][len(1)][0|1]
	   30      Mask Supplier Option            [30][len(1)][0|1]
	   31      Perform Router Discovery Option [31][len(1)][0|1]
	   32      Router Solicitation Addr Option [32][len(4)][a1][a2][a3][a4]
	   33      Static Route Option             [33][len(n)][d1][d2][d3][d4][r1][r2][r3][r4][d1][d2][d3][d4][r1][r2][r3][r4][...]
	   34      Trailer Encapsulation Option    [34][len(1)][0|1]
	   35      ARP Cache Timeout Option        [35][len(4)][t1][t2][t3][t4]
	   36      Ethernet Encapsulation Option   [36][len(1)][0|1]
	   37      TCP Default TTL Option          [37][len(1)][0|1]
	   38      TCP Keepalive Interval Option   [38][len(4)][t1][t2][t3][t4]
	   39      TCP Keepalive Garbage Option    [39][len(1)][0|1]
	   40      Network Info Service Domain Opt [40][len(n)][n1][n2][n3][n4][...]
	   41      Network Info Servers Option     [41][len(n)][a1][a2][a3][a4][a1][a2][...]
	   42      Network Time Proto Servers Opt  [42][len(n)][a1][a2][a3][a4][a1][a2][...]
	   43      Vendor Specific Information     [43][len(n)][i1][i2][...]
	   44      NetBIOS TCP/IP Name Server Opt  [44][len(n)][a1][a2][a3][a4][b1][b2][b3][b4][...]
	   45      NetBIOS TCP/IP Datagram Dist Opt[45][len(n)][a1][a2][a3][a4][b1][b2][b3][b4][...]
	   46      NetBIOS TCP/IP Node Type Option [46][len(1)][node type]
	                                               VALUE   NODE TYPE
	                                               -----   ---------
	                                               0x1     B-node
	                                               0x2     P-node
	                                               0x4     M-node
	                                               0x8     H-node
	   47      NetBIOS TCP/IP Scope Option     [47][len(n)][s1][s2][s3][s4][...]
	   48      X Window System Font Server Opt [48][len(n)][a1][a2][a3][a4][a1][a2][...]
	   49      X Window System Display Mgr Opt [49][len(n)][a1][a2][a3][a4][a1][a2][...]
	   50      Requested IP Address            [50][len(4)][a1][a2][a3][a4]
	   51      IP Address Lease Time           [51][len(4)][t1][t2][t3][t4]
	   52      Option Overload                 [52][len(1)][1|2|3]
	                                               VALUE   MEANING
	                                               -----   -------
	                                               1       the "file" field is used to hold options
	                                               2       the "sname" field is used to hold options
	                                               3       both fields are used to hold options
	   53      DHCP Message Type               [53][len(1)][1-7]
	                                               VALUE   MESSAGE TYPE
	                                               -----   ------------
	                                               1       DHCPDISCOVER
	                                               2       DHCPOFFER
	                                               3       DHCPREQUEST
	                                               4       DHCPDECLINE
	                                               5       DHCPACK
	                                               6       DHCPNAK
	                                               7       DHCPRELEASE
	   54      Server Identifier               [54][len(4)][a1][a2][a3][a4]
	   55      Parameter Request List          [55][len(n)][c1][c2][...]
	   56      Message                         [56][len(n)][c1][c2][...]
	   57      Maximum DHCP Message Size       [57][len(2)[l1][l2]
	   58      Renewal (T1) Time Value         [58][len(4)][t1][t2][t3][t4]
	   59      Rebinding (T2) Time Value       [59][len(4)][t1][t2][t3][t4]
	   60      Class-identifier                [60][len(n)][i1][i2][...]
	   61      Client-identifier               [61][len(n)][t1][i1][i2][...]
	   64      NIS+ Domain Option              [64][len(n)][n1][n2][n3][n4][...]
	   65      NIS+ Servers Option             [65][len(n)][a1][a2][a3][a4][a1][a2][...]
	   68      Mobile IP Home Agent Option     [68][len(n)][a1][a2][a3][a4][...]
	   69      SMTP Server Option              [69][len(n)][a1][a2][a3][a4][a1][a2][...]
	   70      POP3 Server Option              [70][len(n)][a1][a2][a3][a4][a1][a2][...]
	   71      NNTP Server Option              [71][len(n)][a1][a2][a3][a4][a1][a2][...]
	   72      WWW Server Option               [72][len(n)][a1][a2][a3][a4][a1][a2][...]
	   73      Default Finger Server Option    [73][len(n)][a1][a2][a3][a4][a1][a2][...]
	   74      Default IRC Server Option       [74][len(n)][a1][a2][a3][a4][a1][a2][...]
	   75      StreetTalk Server Option        [75][len(n)][a1][a2][a3][a4][a1][a2][...]
	   76      STDA Server Option              [76][len(n)][a1][a2][a3][a4][a1][a2][...]
	   255     End                             [255]
	*/
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
	tmpHeader.rd = 0
	tmpHeader.z = 0
	tmpHeader.rcode = 0
	tmpHeader.qdcount = 1
	tmpHeader.ancount = 0
	tmpHeader.nscount = 0
	tmpHeader.arcount = 0

	var tmpQ DnsQuestion
	tmpQ.qname = append(tmpQ.qname, 9)
	tmpQ.qname = append(tmpQ.qname, []byte("microsoft")...)
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

	fmt.Println("DHCP:")
	DhcpClient("new", [6]byte{0x0D, 0xEA, 0xDC, 0x0F, 0xFE, 0xE0}, "", "", 0, 0, "10.1.0.215")

	util.Er(fmt.Errorf("ERROR TEST"))

}

func ValidateIPv4(input string) (uint32, error) {
	// if valid, returns ipv4 address as uint32, otherwise error
	var ipv4 uint32

	regex := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)\.(\d+)$`)
	if regex.MatchString(input) && len(regex.FindStringSubmatch(input)) == 5 {
		// octet 1
		tmp, err := strconv.ParseUint(regex.FindStringSubmatch(input)[1], 10, 8)
		if err != nil {
			return 0, err
		}
		if tmp > 255 {
			return 0, fmt.Errorf("octet 1 out of range [%d]", tmp)
		}
		tmp <<= 24
		ipv4 = uint32(tmp) & 0xFF000000

		// octet 2
		tmp, err = strconv.ParseUint(regex.FindStringSubmatch(input)[2], 10, 8)
		if err != nil {
			return 0, err
		}
		if tmp > 255 {
			return 0, fmt.Errorf("octet 2 out of range [%d]", tmp)
		}
		tmp <<= 16
		ipv4 += uint32(tmp) & 0x00FF0000

		// octet 3
		tmp, err = strconv.ParseUint(regex.FindStringSubmatch(input)[3], 10, 8)
		if err != nil {
			return 0, err
		}
		if tmp > 255 {
			return 0, fmt.Errorf("octet 3 out of range [%d]", tmp)
		}
		tmp <<= 8
		ipv4 += uint32(tmp) & 0x0000FF00

		// octet 4
		tmp, err = strconv.ParseUint(regex.FindStringSubmatch(input)[4], 10, 8)
		if err != nil {
			return 0, err
		}
		if tmp > 255 {
			return 0, fmt.Errorf("octet 4 out of range [%d]", tmp)
		}
		ipv4 += uint32(tmp) & 0x000000FF
	} else {
		return 0, fmt.Errorf("invalid ipv4 address format [%s]", input)
	}

	return ipv4, nil
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
	//	pattern := regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	//	if !pattern.MatchString(dest) {
	//		return nil, fmt.Errorf("invalid destination IPv4 address [%s]", dest)
	//	}

	_, err := ValidateIPv4(dest)
	if err != nil {
		return nil, err
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
	var flags byte

	datagram = append(datagram, byte(header.id>>8), byte(header.id))

	flags = byte((header.qr & 1) << 7)
	flags += byte((header.opcode & 15) << 3)
	flags += byte((header.aa & 1) << 2)
	flags += byte((header.tc & 1) << 1)
	flags += byte(header.rd & 1)
	datagram = append(datagram, flags)

	flags = byte((header.ra & 1) << 7)
	flags += byte((header.z & 7) << 4)
	flags += byte(header.rcode & 15)
	datagram = append(datagram, flags)

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
	if strings.ToUpper(proto) == "TCP" {
		// do the same for TCP
	}

	return nil, nil
}

func DhcpGenerateDatagram(input DhcpDatagram) []byte {
	var datagram []byte

	datagram = append(datagram, input.op)
	datagram = append(datagram, input.htype)
	datagram = append(datagram, input.hlen)
	datagram = append(datagram, input.hops)
	datagram = append(datagram, byte(input.xid>>24), byte(input.xid>>16), byte(input.xid>>8), byte(input.xid))
	datagram = append(datagram, byte(input.secs>>8), byte(input.secs))
	datagram = append(datagram, byte(input.flags>>8), byte(input.flags))
	datagram = append(datagram, byte(input.ciaddr>>24), byte(input.ciaddr>>16), byte(input.ciaddr>>8), byte(input.ciaddr))
	datagram = append(datagram, byte(input.yiaddr>>24), byte(input.yiaddr>>16), byte(input.yiaddr>>8), byte(input.yiaddr))
	datagram = append(datagram, byte(input.siaddr>>24), byte(input.siaddr>>16), byte(input.siaddr>>8), byte(input.siaddr))
	datagram = append(datagram, byte(input.giaddr>>24), byte(input.giaddr>>16), byte(input.giaddr>>8), byte(input.giaddr))
	for i := 0; i < len(input.chaddr); i++ {
		datagram = append(datagram, input.chaddr[i])
	}
	for i := 0; i < len(input.sname); i++ {
		datagram = append(datagram, input.sname[i])
	}
	for i := 0; i < len(input.file); i++ {
		datagram = append(datagram, input.file[i])
	}
	for i := 0; i < len(input.options); i++ {
		datagram = append(datagram, input.options[i])
	}

	return datagram
}

func DhcpClient(action string, mac [6]byte, srcIP string, dstIP string, clientPort uint16, serverPort uint16, requestedIP string) (string, error) {
	if srcIP == "" {
		srcIP = "0.0.0.0"
	} else {
		_, err := ValidateIPv4(srcIP)
		if err != nil {
			return "", err
		}
	}
	if dstIP == "" {
		dstIP = "255.255.255.255"
	} else {
		_, err := ValidateIPv4(dstIP)
		if err != nil {
			return "", err
		}
	}
	if requestedIP == "" {
		requestedIP = "0.0.0.0"
	}
	if clientPort == 0 {
		clientPort = 68
	}
	if serverPort == 0 {
		serverPort = 67
	}

	var buffSize = 65507

	switch action {
	case "new":
		// DHCP DISCOVER
		var discoverDatagram DhcpDatagram
		discoverDatagram.op = 1
		discoverDatagram.htype = 1
		discoverDatagram.hlen = 6
		discoverDatagram.hops = 0
		discoverDatagram.xid = 0x0C0FFEE0
		discoverDatagram.secs = 0
		discoverDatagram.flags = 0
		discoverDatagram.ciaddr = 0
		discoverDatagram.yiaddr = 0
		discoverDatagram.siaddr = 0
		discoverDatagram.giaddr = 0
		discoverDatagram.chaddr[0] = mac[0]
		discoverDatagram.chaddr[1] = mac[1]
		discoverDatagram.chaddr[2] = mac[2]
		discoverDatagram.chaddr[3] = mac[3]
		discoverDatagram.chaddr[4] = mac[4]
		discoverDatagram.chaddr[5] = mac[5]
		discoverDatagram.options = append(discoverDatagram.options, 99, 130, 83, 99)                                          // magic cookie
		discoverDatagram.options = append(discoverDatagram.options, 53, 1, 1)                                                 // DHCP DISCOVER
		discoverDatagram.options = append(discoverDatagram.options, 61, 7, 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]) // Client Identifier
		if requestedIP == "0.0.0.0" {
			discoverDatagram.options = append(discoverDatagram.options, 50, 4, 0, 0, 0, 0) // Requested IP Address
		} else {
			rqstIP, err := ValidateIPv4(requestedIP)
			if err != nil {
				return "", err
			}
			discoverDatagram.options = append(discoverDatagram.options, 50, 4, byte(rqstIP<<24), byte(rqstIP<<16), byte(rqstIP<<8), byte(rqstIP))
		}
		discoverDatagram.options = append(discoverDatagram.options, 55, 6, 1, 6, 15, 44, 3, 42) // Parameter Request List
		discoverDatagram.options = append(discoverDatagram.options, 255)                        // END

		util.Debug("Building DHCP DISCOVER", true)

		datagram := DhcpGenerateDatagram(discoverDatagram)
		for len(datagram)%16 != 0 {
			datagram = append(datagram, 0)
		}
		util.Debug(fmt.Sprintf("Datagram:\n%s", util.WalkByteSlice(datagram)), true)

		util.Debug("Resolving local address", true)
		clientAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", srcIP, clientPort))
		if err != nil {
			return "", err
		}
		util.Debug("Resolving remote address", true)
		serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dstIP, serverPort))
		if err != nil {
			return "", err
		}

		util.Debug(fmt.Sprintf("Creating socket [%s:%d] <--> [%s:%d]", srcIP, clientPort, dstIP, serverPort), true)
		conn, err := net.DialUDP("udp", clientAddr, serverAddr)
		if err != nil {
			return "", err
		}
		defer conn.Close()

		util.Debug("Sending datagram to server", true)
		nBytes, err := conn.Write(datagram)
		if err != nil {
			return "", err
		}
		util.Debug(fmt.Sprintf("%d Bytes sent", nBytes), true)

		buf := make([]byte, buffSize)

		for {
			n, rmtAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return "", err
			}
			util.Debug(fmt.Sprintf("Received %d bytes from %s", n, rmtAddr), true)
			util.Debug(fmt.Sprintf("Datagram:\n%s", util.WalkByteSlice(buf[:n])), true)

			var replyDatagram DhcpDatagram
			if len(buf[:n]) < 237 {
				return "", fmt.Errorf("malformed datagram, length too short [%d]", len(buf[:n]))
			}
			replyDatagram.op = buf[1]
			replyDatagram.htype = buf[2]
			replyDatagram.hlen = buf[3]
			replyDatagram.hops = buf[4]
			replyDatagram.xid = (uint32(buf[5]) << 24) + (uint32(buf[6]) << 16) + (uint32(buf[7]) << 8) + uint32(buf[8])
			replyDatagram.secs = (uint16(buf[9]) << 8) + uint16(buf[10])
			replyDatagram.flags = (uint16(buf[11]) << 8) + uint16(buf[12])
			replyDatagram.ciaddr = (uint32(buf[13]) << 24) + (uint32(buf[14]) << 16) + (uint32(buf[15]) << 8) + uint32(buf[16])
			replyDatagram.yiaddr = (uint32(buf[17]) << 24) + (uint32(buf[18]) << 16) + (uint32(buf[19]) << 8) + uint32(buf[20])
			replyDatagram.siaddr = (uint32(buf[21]) << 24) + (uint32(buf[22]) << 16) + (uint32(buf[23]) << 8) + uint32(buf[24])
			replyDatagram.giaddr = (uint32(buf[25]) << 24) + (uint32(buf[26]) << 16) + (uint32(buf[27]) << 8) + uint32(buf[28])
			for i := 0; i < 16; i++ {
				replyDatagram.chaddr[i] = buf[29+i]
			}
			for i := 0; i < 64; i++ {
				replyDatagram.sname[i] = buf[45+i]
			}
			for i := 0; i < 128; i++ {
				replyDatagram.file[i] = buf[109+i]
			}
			for i := 0; i < len(buf[237:n]); i++ {
				replyDatagram.options = append(replyDatagram.options, buf[i])
			}

			if replyDatagram.op != 2 {
				util.Debug("Datagram [OP] is not BOOT REPLY, ignoring", true)
				continue
			}
			if replyDatagram.htype != 1 {
				util.Debug("Datagram [HTYPE] is not Ethernet, ignoring", true)
				continue
			}
			if replyDatagram.hlen != 6 {
				util.Debug("Datagram [HLEN] is not 6, ignoring", true)
				continue
			}
			if replyDatagram.xid != discoverDatagram.xid {
				util.Debug("Datagram [XID] dosen't match, ignoring", true)
				continue
			}
			// parse options
			for i := 237; i < len(buf[:n]); i++ {
				switch buf[i] {
				case 0:
					continue
				case 255:
					break
				case 53:
					if i+2 < len(buf[:n]) {
						if buf[i+1] != 1 {
							util.Debug("Malformed DHCP message type", true)
							break
						}
						if buf[i+2] > 7 {
							util.Debug("Malformed DHCP message type", true)
							break
						}
						switch buf[i+2] {
						case 1:
							util.Debug("DHCP Message Type: DISCOVER, ignoring", true)
							continue
						case 2:
							util.Debug("DHCP Message Type: OFFER received", true)

							var subnetMask uint32
							var routers []uint32
							var dns []uint32
							var domainName []uint32
							var ntp []uint32

							for i := 0; i < len(buf[:n]); i++ {
								switch buf[i] {
								case 1: // Subnet Mask
									if i+6 < len(buf[:n]) {
										if buf[i+1] != 4 || buf[i+2] > 255 || buf[i+3] > 255 || buf[i+4] > 255 || buf[i+5] > 255 {
											util.Debug("Malformed DHCP Option, Subnet Mask, ignoring", true)
											break
										}
										subnetMask = (uint32(buf[i+2]) << 24) + (uint32(buf[i+3]) << 16) + (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
										i += 5
										continue
									} else {
										util.Debug("Malformed DHCP Option, Subnet Mask, ignoring", true)
										break
									}
								case 3: // Router
									if i+6 < len(buf[:n]) {
										for j := i + 2; j < int(buf[i+1]); j += 4 {
											if j+3 < len(buf[:n]) {
												tmpRouter := (uint32(buf[j]) << 24) + (uint32(buf[j+1]) << 16) + (uint32(buf[j+2]) << 8) + uint32(buf[j+3])
												routers = append(routers, tmpRouter)
											} else {
												util.Debug("Malformed DHCP Option, Router, ignoring", true)
												break
											}
										}
										i += int(buf[i+1])
										continue
									} else {
										util.Debug("Malformed DHCP Option, Router, ignoring", true)
										break
									}
								case 6: // DNS Servers
									if i+6 < len(buf[:n]) {
										for j := i + 2; j < int(buf[i+1]); j += 4 {
											if j+3 < len(buf[:n]) {
												tmpDns := (uint32(buf[j]) << 24) + (uint32(buf[j+1]) << 16) + (uint32(buf[j+2]) << 8) + uint32(buf[j+3])
												dns = append(dns, tmpDns)
											} else {
												util.Debug("Malformed DHCP Option, DNS, ignoring", true)
												break
											}
										}
										i += int(buf[i+1])
										continue
									} else {
										util.Debug("Malformed DHCP Option, DNS, ignoring", true)
										break
									}
								case 15: // Domain Name
									if i+6 < len(buf[:n]) {
										for j := i + 2; j < int(buf[i+1]); j += 4 {
											if j+3 < len(buf[:n]) {
												tmpDomainName := (uint32(buf[j]) << 24) + (uint32(buf[j+1]) << 16) + (uint32(buf[j+2]) << 8) + uint32(buf[j+3])
												domainName = append(domainName, tmpDomainName)
											} else {
												util.Debug("Malformed DHCP Option, Domain Name, ignoring", true)
												break
											}
										}
										i += int(buf[i+1])
										continue
									} else {
										util.Debug("Malformed DHCP Option, Domain Name, ignoring", true)
										break
									}
								case 42: // NTP
									if i+6 < len(buf[:n]) {
										for j := i + 2; j < int(buf[i+1]); j += 4 {
											if j+3 < len(buf[:n]) {
												tmpNtp := (uint32(buf[j]) << 24) + (uint32(buf[j+1]) << 16) + (uint32(buf[j+2]) << 8) + uint32(buf[j+3])
												ntp = append(ntp, tmpNtp)
											} else {
												util.Debug("Malformed DHCP Option, NTP, ignoring", true)
												break
											}
										}
										i += int(buf[i+1])
										continue
									} else {
										util.Debug("Malformed DHCP Option, NTP, ignoring", true)
										break
									}
								case 44:
								case 50:
								case 55:
								case 61:
								default:
									util.Debug(fmt.Sprintf("Ignoring DHCP Option: [%d]", buf[i]), true)
								}
							}
						case 3:
							util.Debug("DHCP Message Type: REQUEST, ignoring", true)
							continue
						case 4:
							util.Debug("DHCP Message Type: DECLINE, ignoring", true)
							continue
						case 5:
							util.Debug("DHCP Message Type: ACK, ignoring", true)
							continue
						case 6:
							util.Debug("DHCP Message Type: NAK, trying new address", true)
							return DhcpClient(action, mac, srcIP, dstIP, clientPort, serverPort, "")
						case 7:
							util.Debug("DHCP Message Type: RELEASE, ignoring", true)
							continue
						}
					} else {
						util.Debug("Malformed DHCP message type", true)
						break
					}
				}
			}
		}

	case "renew":
	case "release":
	default:
		return "", fmt.Errorf("no valid action given [%s]", action)
	}

	return "test", nil
}
