// This file is part of latency-proxy-detect's changes to zerotrace and is
// covered by the MPL-2.0 like the rest of this directory.

package zerotrace

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

const isnTTL = 10 * time.Minute

var errNoISN = errors.New("SYN/ACK of this connection was not captured")

type isnEntry struct {
	serverISN  uint32 // sequence number of our SYN/ACK
	clientNext uint32 // acknowledgement number of our SYN/ACK (client ISN + 1)
	seen       time.Time
}

// isnTable remembers the initial sequence numbers of recent connections,
// learnt from the SYN/ACK segments we send.
type isnTable struct {
	sync.Mutex
	m map[string]isnEntry
}

func newISNTable() *isnTable { return &isnTable{m: map[string]isnEntry{}} }

func isnKey(localPort uint16, remoteIP net.IP, remotePort uint16) string {
	return fmt.Sprintf("%d|%s|%d", localPort, remoteIP.To4(), remotePort)
}

// observe records the packet if it is a SYN/ACK we sent. It reports whether
// the packet was a SYN/ACK (and so needs no further processing).
func (t *isnTable) observe(pkt gopacket.Packet) bool {
	if pkt == nil {
		return false
	}
	tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || tcp == nil || !tcp.SYN || !tcp.ACK {
		return false
	}
	ip, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || ip == nil {
		return true
	}
	t.Lock()
	t.m[isnKey(uint16(tcp.SrcPort), ip.DstIP, uint16(tcp.DstPort))] = isnEntry{
		serverISN:  tcp.Seq,
		clientNext: tcp.Ack,
		seen:       time.Now(),
	}
	t.Unlock()
	return true
}

func (t *isnTable) expire() {
	t.Lock()
	defer t.Unlock()
	for k, e := range t.m {
		if time.Since(e.seen) > isnTTL {
			delete(t.m, k)
		}
	}
}

func (t *isnTable) get(key string) (isnEntry, bool) {
	t.Lock()
	defer t.Unlock()
	e, ok := t.m[key]
	return e, ok
}

// seqAck returns the sequence number of the first unacknowledged byte we
// sent (snd_una) and the next byte we expect from the client (rcv_nxt).
func (z *ZeroTrace) seqAck(conn *net.TCPConn) (uint32, uint32, error) {
	local, ok1 := conn.LocalAddr().(*net.TCPAddr)
	remote, ok2 := conn.RemoteAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return 0, 0, errors.New("not a TCP connection")
	}
	e, ok := z.isns.get(isnKey(uint16(local.Port), remote.IP, uint16(remote.Port)))
	if !ok {
		return 0, 0, errNoISN
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var info *unix.TCPInfo
	var serr error
	if err := raw.Control(func(fd uintptr) {
		info, serr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil {
		return 0, 0, err
	}
	if serr != nil {
		return 0, 0, serr
	}
	seq := e.serverISN + 1 + uint32(info.Bytes_acked)
	ack := e.clientNext + uint32(info.Bytes_received)
	return seq, ack, nil
}
