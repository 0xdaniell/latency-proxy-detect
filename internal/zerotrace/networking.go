// This file is derived from github.com/brave/zerotrace (MPL-2.0) and was
// modified for latency-proxy-detect. See LICENSE-MPL-2.0 in this directory.

package zerotrace

import (
	"net"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

const (
	ipv4Version = uint8(4)
	// window is the receive window our trace packets advertise. The value is
	// shifted by the connection's window scale on the client side; a
	// generous value keeps the client from throttling.
	window = 0xffff
)

// createPkt returns the TCP header of a trace packet for the given
// connection. The packet is a pure ACK carrying the connection's current
// sequence and acknowledgement numbers, so stateful firewalls and NAT boxes
// (Linux conntrack in particular) treat it as part of the connection and
// forward it, and the client discards it as a duplicate ACK. Unlike the
// original 0trace, which sent sequence number 0 and a payload, this neither
// gets dropped as "invalid" nor corrupts the connection.
func createPkt(conn net.Conn, seq, ack uint32) ([]byte, error) {
	// Extract hosts and ports from our net.Conn object.
	srcIP, strSrcPort, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	dstIP, strDstPort, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}

	// Convert ports from string to int.
	srcPort, err := strconv.ParseUint(strSrcPort, 10, 16)
	if err != nil {
		return nil, err
	}
	dstPort, err := strconv.ParseUint(strDstPort, 10, 16)
	if err != nil {
		return nil, err
	}

	// Compose the pseudo header that's necessary for computing the TCP header
	// checksum.
	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Window:  window,
		ACK:     true,
		Seq:     seq,
		Ack:     ack,
	}
	if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return nil, err
	}

	// Serialize our packet.
	buf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, options, tcpLayer); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// createRawIpConn returns a new raw IPv4 connection.  We (ab)use
// net.ListenPacket to get a raw socket.  We only care about sending packets and
// not about receiving them, so we use ip4:89 (OSPF) to "receive" packets that
// we are unlikely to encounter.
func createRawIpConn() (*ipv4.RawConn, error) {
	c, err := net.ListenPacket("ip4:89", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	r, err := ipv4.NewRawConn(c)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// newIpv4Header returns a new IPv4 header.
func newIpv4Header(ttl, id int, dstAddr net.IP, payloadLen int) *ipv4.Header {
	return &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + payloadLen, // payload = TCP header + data
		ID:       id,
		TTL:      ttl,
		Protocol: 6, // TCP
		Dst:      dstAddr,
	}
}
