package main

import "time"

// The decision tree from Figure 6 of "CalcuLatency: Leveraging Cross-Layer
// Network Latency Measurements to Detect Proxy-Enabled Abuse" (Ramesh,
// Winter, Korman, Ensafi; USENIX Security 2024).
//
// It picks which network-layer RTT to compare against the application-layer
// (WebSocket) RTT and returns the difference. A large difference means the
// browser that answered the WebSocket pings sits behind the host that answered
// the network-layer probes, i.e. behind a proxy or VPN.

// closeEnough is how near two RTTs must be to count as "the same path".
const closeEnough = 10 * time.Millisecond

// Labels name the leaf of the decision tree that produced the difference.
const (
	LabelWsICMP             = "WsICMP"
	LabelWs0TClient         = "Ws0TClient"
	LabelWs0TNetwork        = "Ws0TNetwork"
	LabelBestEffortWs0T     = "BestEffortWs0T"
	LabelE2EWsTCPICMP       = "E2EWsTCPICMP"
	LabelE2EWsTCP0T         = "E2EWsTCP0t"
	LabelE2EWs0TClient      = "E2EWs0tClient"
	LabelE2EBestEffortWsTCP = "E2EBestEffortWsTCP"
	LabelNoData             = "NoData"
)

// Verdicts shown to the visitor.
const (
	VerdictDirect       = "direct"       // difference below the threshold
	VerdictProxy        = "proxy"        // difference above the threshold
	VerdictInconclusive = "inconclusive" // best-effort leaf or missing data
)

// Inputs holds the four measurements. A nil pointer means "not measured".
type Inputs struct {
	WS  *time.Duration // minimum WebSocket echo RTT (application layer)
	TCP *time.Duration // TCP handshake RTT (transport layer)
	// ICMP is the minimum ICMP echo RTT to the connecting IP (network layer).
	ICMP *time.Duration
	// ZeroTrace is the RTT to the farthest hop 0trace reached (network layer).
	ZeroTrace *time.Duration
	// ZeroTraceReachedClient is true if 0trace got an answer from the
	// connecting IP itself.
	ZeroTraceReachedClient bool
	// ZeroTraceSameNetwork is true if the farthest 0trace hop is in the same
	// autonomous system as the connecting IP.
	ZeroTraceSameNetwork bool
}

// Decision is the outcome of the decision tree.
type Decision struct {
	Label      string        `json:"label"`
	Diff       time.Duration `json:"-"`
	BestEffort bool          `json:"bestEffort"`
	Verdict    string        `json:"verdict"`
}

func near(a, b time.Duration) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < closeEnough
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// Decide runs the decision tree and applies the threshold.
func Decide(in Inputs, threshold time.Duration) Decision {
	d := decide(in)
	switch {
	case d.Label == LabelNoData:
		d.Verdict = VerdictInconclusive
	case d.BestEffort && d.Diff <= threshold:
		// A best-effort RTT belongs to a hop on the path *before* the
		// connecting address, so it can only be lower than the RTT to that
		// address, and the difference can only be smaller in truth. A small
		// upper bound is therefore conclusive. (This refines the paper,
		// which sets every best-effort case aside.)
		d.Verdict = VerdictDirect
	case d.BestEffort:
		d.Verdict = VerdictInconclusive
	case d.Diff > threshold:
		d.Verdict = VerdictProxy
	default:
		d.Verdict = VerdictDirect
	}
	return d
}

func decide(in Inputs) Decision {
	if in.WS == nil {
		return Decision{Label: LabelNoData}
	}
	ws := *in.WS

	// No TCP sample: treat it like the "TCP ≈ WS" branch, which never uses TCP.
	if in.TCP == nil || near(*in.TCP, ws) || *in.TCP > ws {
		// Network-layer proxy (VPN) or a direct connection: the TCP handshake
		// went end to end, so compare WS with a network-layer RTT.
		switch {
		case in.ICMP != nil:
			return Decision{Label: LabelWsICMP, Diff: ws - *in.ICMP}
		case in.ZeroTrace != nil && in.ZeroTraceReachedClient:
			return Decision{Label: LabelWs0TClient, Diff: ws - *in.ZeroTrace}
		case in.ZeroTrace != nil && in.ZeroTraceSameNetwork:
			return Decision{Label: LabelWs0TNetwork, Diff: ws - *in.ZeroTrace}
		case in.ZeroTrace != nil:
			return Decision{Label: LabelBestEffortWs0T, Diff: ws - *in.ZeroTrace, BestEffort: true}
		default:
			return Decision{Label: LabelNoData}
		}
	}

	// TCP is clearly faster than WS: the TCP connection ended at an
	// application- or transport-layer proxy.
	tcp := *in.TCP
	switch {
	case in.ICMP != nil && near(tcp, *in.ICMP):
		return Decision{Label: LabelE2EWsTCPICMP, Diff: ws - minDur(tcp, *in.ICMP)}
	case in.ZeroTrace != nil && near(tcp, *in.ZeroTrace):
		return Decision{Label: LabelE2EWsTCP0T, Diff: ws - minDur(tcp, *in.ZeroTrace)}
	case in.ZeroTrace != nil && in.ZeroTraceReachedClient:
		return Decision{Label: LabelE2EWs0TClient, Diff: ws - *in.ZeroTrace}
	default:
		return Decision{Label: LabelE2EBestEffortWsTCP, Diff: ws - tcp, BestEffort: true}
	}
}

// maxDistanceKm is an upper bound on the visitor-to-proxy distance implied by
// an RTT difference, using the 4/9·c "speed of the Internet" from
// Katz-Bassett et al. (IMC 2006): about 66.6 km per millisecond of RTT.
func maxDistanceKm(diff time.Duration) float64 {
	if diff <= 0 {
		return 0
	}
	const kmPerMsRTT = 299792.458 * 4 / 9 / 1000 / 2
	return float64(diff.Microseconds()) / 1000 * kmPerMsRTT
}
