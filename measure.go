package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"latency-proxy-detect/internal/zerotrace"
)

// Messages on the WebSocket. The browser must echo every ping's nonce, so it
// cannot answer before a ping has arrived (the paper's "anticipatory response"
// defence).
type wsMsg struct {
	Type   string  `json:"type"`
	ID     string  `json:"id,omitempty"`
	Seq    int     `json:"seq"`
	Nonce  string  `json:"nonce,omitempty"`
	Pings  int     `json:"pings,omitempty"`
	Stage  string  `json:"stage,omitempty"`
	Result *Result `json:"result,omitempty"`
	Error  string  `json:"error,omitempty"`
}

// RTTs reports every measurement in milliseconds; null means "no answer".
type RTTs struct {
	WebSocketMs            *float64 `json:"webSocketMs"`
	WebSocketSamples       int      `json:"webSocketSamples"`
	TCPHandshakeMs         *float64 `json:"tcpHandshakeMs"`
	ICMPMs                 *float64 `json:"icmpMs"`
	ZeroTraceMs            *float64 `json:"zeroTraceMs"`
	ZeroTraceHop           string   `json:"zeroTraceHop,omitempty"`
	ZeroTraceHopTTL        int      `json:"zeroTraceHopTTL,omitempty"`
	ZeroTraceReachedClient bool     `json:"zeroTraceReachedClient"`
	ZeroTraceSameNetwork   bool     `json:"zeroTraceSameNetwork"`
}

// Result is what the visitor sees and what the log stores.
type Result struct {
	ID            string    `json:"id"`
	Time          time.Time `json:"time"`
	IP            string    `json:"ip"`
	Verdict       string    `json:"verdict"`
	Label         string    `json:"label"`
	BestEffort    bool      `json:"bestEffort"`
	DiffMs        *float64  `json:"diffMs"`
	ThresholdMs   float64   `json:"thresholdMs"`
	MaxDistanceKm *float64  `json:"maxDistanceKm,omitempty"`
	RTT           RTTs      `json:"rtt"`
}

type measurer struct {
	cfg    *config
	zt     *zerotrace.ZeroTrace
	pinger *pinger
	asn    *asnLookup
	store  *store

	slots  chan struct{} // limits concurrent measurements
	mu     sync.Mutex
	active map[string]bool // one measurement per client IP at a time
}

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func msPtr(d *time.Duration) *float64 {
	if d == nil {
		return nil
	}
	v := float64(d.Microseconds()) / 1000
	return &v
}

func (m *measurer) acquire(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active[ip] {
		return false
	}
	select {
	case m.slots <- struct{}{}:
	default:
		return false
	}
	m.active[ip] = true
	return true
}

func (m *measurer) release(ip string) {
	m.mu.Lock()
	delete(m.active, ip)
	m.mu.Unlock()
	<-m.slots
}

func (m *measurer) handleWS(w http.ResponseWriter, r *http.Request) {
	up := websocket.Upgrader{CheckOrigin: m.cfg.originAllowed}
	ws, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	host, _, err := net.SplitHostPort(ws.NetConn().RemoteAddr().String())
	if err != nil {
		return
	}
	clientIP := net.ParseIP(host).To4()
	if clientIP == nil {
		_ = ws.WriteJSON(wsMsg{Type: "error", Error: "Only IPv4 visitors can be measured (0trace is IPv4-only)."})
		return
	}
	if !m.acquire(host) {
		_ = ws.WriteJSON(wsMsg{Type: "error", Error: "Busy: a measurement for your address is already running, or the server is at capacity. Try again in a minute."})
		return
	}
	defer m.release(host)

	var (
		tcpRTT  *time.Duration
		tcpConn *net.TCPConn
	)
	if hc, ok := r.Context().Value(connCtxKey{}).(*handshakeConn); ok {
		tcpRTT = hc.handshakeRTT
		tcpConn, _ = hc.Conn.(*net.TCPConn)
	}

	res := &Result{ID: newID(), Time: time.Now().UTC(), IP: m.cfg.displayIP(clientIP), ThresholdMs: float64(m.cfg.threshold.Milliseconds())}
	if err := ws.WriteJSON(wsMsg{Type: "hello", ID: res.ID, Pings: m.cfg.pings}); err != nil {
		return
	}

	// Network layer, part 1: ICMP echo, in parallel with the WebSocket pings.
	icmpDone := make(chan *time.Duration, 1)
	go func() { icmpDone <- m.pinger.minPing(clientIP, m.cfg.icmpCount, 1500*time.Millisecond) }()

	// Application layer: WebSocket echo with nonces.
	wsRTT, samples := m.webSocketRTT(ws)

	// Network layer, part 2: 0trace on this very TCP connection. It runs
	// last, once the connection is quiet, so that every byte has been
	// acknowledged and the probes carry current sequence numbers. If the
	// connection dies anyway, the browser fetches the result over a new one.
	_ = ws.WriteJSON(wsMsg{Type: "status", Stage: "network"})
	var zt *zerotrace.Result
	if m.zt != nil && tcpConn != nil {
		time.Sleep(quietPeriod(wsRTT))
		zt, err = m.zt.CalcRTT(tcpConn)
		if err != nil {
			zt = nil
		}
	}
	icmpRTT := <-icmpDone

	in := Inputs{WS: wsRTT, TCP: tcpRTT, ICMP: icmpRTT}
	res.RTT = RTTs{
		WebSocketMs: msPtr(wsRTT), WebSocketSamples: samples,
		TCPHandshakeMs: msPtr(tcpRTT), ICMPMs: msPtr(icmpRTT),
	}
	if zt != nil {
		in.ZeroTrace = &zt.RTT
		in.ZeroTraceReachedClient = zt.ReachedTarget
		res.RTT.ZeroTraceMs = msPtr(&zt.RTT)
		res.RTT.ZeroTraceHop = zt.HopIP.String()
		res.RTT.ZeroTraceHopTTL = zt.HopTTL
		res.RTT.ZeroTraceReachedClient = zt.ReachedTarget
		// The AS lookup is only needed when nothing better is available.
		if icmpRTT == nil && !zt.ReachedTarget && m.asn != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			in.ZeroTraceSameNetwork = m.asn.sameAS(ctx, clientIP, zt.HopIP)
			cancel()
			res.RTT.ZeroTraceSameNetwork = in.ZeroTraceSameNetwork
		}
	}

	d := Decide(in, m.cfg.threshold)
	res.Verdict, res.Label, res.BestEffort = d.Verdict, d.Label, d.BestEffort
	if d.Label != LabelNoData {
		res.DiffMs = msPtr(&d.Diff)
		if d.Diff > 0 {
			km := float64(int(maxDistanceKm(d.Diff)))
			res.MaxDistanceKm = &km
		}
	}

	m.store.add(res, r.UserAgent())
	_ = ws.WriteJSON(wsMsg{Type: "result", Result: res})
	_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done"), time.Now().Add(time.Second))
}

// webSocketRTT sends cfg.pings nonce-carrying pings and returns the minimum
// echo time and how many echoes came back.
func (m *measurer) webSocketRTT(ws *websocket.Conn) (*time.Duration, int) {
	type ping struct {
		nonce string
		sent  time.Time
	}
	var (
		mu    sync.Mutex
		sent  = make(map[int]ping, m.cfg.pings)
		best  *time.Duration
		count int
		done  = make(chan struct{})
	)

	go func() {
		defer close(done)
		for {
			var msg wsMsg
			if err := ws.ReadJSON(&msg); err != nil {
				return
			}
			now := time.Now()
			if msg.Type != "pong" {
				continue
			}
			mu.Lock()
			p, ok := sent[msg.Seq]
			if ok && p.nonce == msg.Nonce {
				delete(sent, msg.Seq)
				rtt := now.Sub(p.sent)
				if best == nil || rtt < *best {
					best = &rtt
				}
				count++
			}
			finished := count == m.cfg.pings
			mu.Unlock()
			if finished {
				return
			}
		}
	}()

	for i := 0; i < m.cfg.pings; i++ {
		var b [8]byte
		_, _ = rand.Read(b[:])
		nonce := hex.EncodeToString(b[:])
		mu.Lock()
		sent[i] = ping{nonce: nonce, sent: time.Now()}
		mu.Unlock()
		if err := ws.WriteJSON(wsMsg{Type: "ping", Seq: i, Nonce: nonce}); err != nil {
			break
		}
		select {
		case <-done:
		case <-time.After(m.cfg.pingInterval):
		}
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	// Unblock the reader if it is still waiting for stragglers.
	_ = ws.SetReadDeadline(time.Now())
	<-done
	_ = ws.SetReadDeadline(time.Time{})

	mu.Lock()
	defer mu.Unlock()
	return best, count
}

type connCtxKey struct{}

// quietPeriod is how long to wait for the client to acknowledge everything
// we sent before 0trace reads the sequence numbers: one round trip plus
// slack.
func quietPeriod(wsRTT *time.Duration) time.Duration {
	d := 300 * time.Millisecond
	if wsRTT != nil {
		d += 2 * *wsRTT
	}
	return d
}
