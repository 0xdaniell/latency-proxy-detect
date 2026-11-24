package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// Transport layer: the TCP handshake RTT.
//
// For a passive open, Linux takes its first RTT sample from the time between
// sending SYN/ACK and receiving the client's ACK. Reading TCP_INFO right after
// accept(), before we send a single byte, returns exactly that sample.

type handshakeConn struct {
	net.Conn
	handshakeRTT *time.Duration
}

type handshakeListener struct{ net.Listener }

func (l handshakeListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	hc := &handshakeConn{Conn: c}
	if tc, ok := c.(*net.TCPConn); ok {
		if rtt, err := tcpInfoRTT(tc); err == nil && rtt > 0 {
			hc.handshakeRTT = &rtt
		}
	}
	return hc, nil
}

func tcpInfoRTT(c *net.TCPConn) (time.Duration, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var info *unix.TCPInfo
	var serr error
	if err := raw.Control(func(fd uintptr) {
		info, serr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	return time.Duration(info.Rtt) * time.Microsecond, nil
}

// ---------------------------------------------------------------------------
// Network layer: ICMP echo.

type pinger struct {
	conn *icmp.PacketConn
	id   int

	mu      sync.Mutex
	seq     uint16
	waiting map[uint16]chan time.Time
}

func newPinger() (*pinger, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	var b [2]byte
	_, _ = rand.Read(b[:])
	p := &pinger{conn: c, id: int(binary.BigEndian.Uint16(b[:])), waiting: map[uint16]chan time.Time{}}
	go p.readLoop()
	return p, nil
}

func (p *pinger) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, _, err := p.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		now := time.Now()
		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok || echo.ID != p.id {
			continue
		}
		p.mu.Lock()
		ch := p.waiting[uint16(echo.Seq)]
		delete(p.waiting, uint16(echo.Seq))
		p.mu.Unlock()
		if ch != nil {
			ch <- now
		}
	}
}

// ping sends one echo request and returns its RTT.
func (p *pinger) ping(dst net.IP, timeout time.Duration) (time.Duration, error) {
	ch := make(chan time.Time, 1)
	p.mu.Lock()
	p.seq++
	seq := p.seq
	p.waiting[seq] = ch
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.waiting, seq)
		p.mu.Unlock()
	}()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: p.id, Seq: int(seq), Data: []byte("latency-proxy-detect")},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}
	sent := time.Now()
	if _, err := p.conn.WriteTo(b, &net.IPAddr{IP: dst}); err != nil {
		return 0, err
	}
	select {
	case recvd := <-ch:
		return recvd.Sub(sent), nil
	case <-time.After(timeout):
		return 0, errors.New("timeout")
	}
}

// minPing sends count echo requests, one at a time, and returns the minimum
// RTT, or nil if none was answered.
func (p *pinger) minPing(dst net.IP, count int, timeout time.Duration) *time.Duration {
	var best *time.Duration
	for i := 0; i < count; i++ {
		rtt, err := p.ping(dst, timeout)
		if err != nil {
			continue
		}
		if best == nil || rtt < *best {
			r := rtt
			best = &r
		}
	}
	return best
}

// ---------------------------------------------------------------------------
// Autonomous system lookup, used to tell whether 0trace stopped inside the
// client's own network. Uses RIPEstat, as the paper does.

type asnLookup struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string][]string
}

func newASNLookup() *asnLookup {
	return &asnLookup{client: &http.Client{Timeout: 4 * time.Second}, cache: map[string][]string{}}
}

func (a *asnLookup) asns(ctx context.Context, ip net.IP) ([]string, error) {
	key := ip.String()
	a.mu.Lock()
	if v, ok := a.cache[key]; ok {
		a.mu.Unlock()
		return v, nil
	}
	a.mu.Unlock()

	url := "https://stat.ripe.net/data/network-info/data.json?resource=" + key
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ripestat: %s", resp.Status)
	}
	var body struct {
		Data struct {
			ASNs []string `json:"asns"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	a.mu.Lock()
	if len(a.cache) > 10000 {
		a.cache = map[string][]string{}
	}
	a.cache[key] = body.Data.ASNs
	a.mu.Unlock()
	return body.Data.ASNs, nil
}

func (a *asnLookup) sameAS(ctx context.Context, x, y net.IP) bool {
	ax, err := a.asns(ctx, x)
	if err != nil || len(ax) == 0 {
		return false
	}
	ay, err := a.asns(ctx, y)
	if err != nil {
		return false
	}
	for _, p := range ax {
		for _, q := range ay {
			if p == q {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------

// defaultInterface returns the interface that carries the IPv4 default route.
func defaultInterface() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) > 2 && fields[1] == "00000000" {
			return fields[0], nil
		}
	}
	return "", errors.New("no IPv4 default route")
}
