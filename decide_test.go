package main

import (
	"testing"
	"time"
)

func ms(n int) *time.Duration {
	d := time.Duration(n) * time.Millisecond
	return &d
}

func TestDecide(t *testing.T) {
	const threshold = 50 * time.Millisecond
	cases := []struct {
		name    string
		in      Inputs
		label   string
		diffMs  int
		verdict string
	}{
		{
			// The paper's example: India -> VPN in Canada -> server in the U.S.
			name:  "VPN, ICMP answered by the VPN server",
			in:    Inputs{WS: ms(250), TCP: ms(248), ICMP: ms(35)},
			label: LabelWsICMP, diffMs: 215, verdict: VerdictProxy,
		},
		{
			name:  "direct, ICMP answered",
			in:    Inputs{WS: ms(42), TCP: ms(40), ICMP: ms(39)},
			label: LabelWsICMP, diffMs: 3, verdict: VerdictDirect,
		},
		{
			name:  "direct, no ICMP, 0trace reached the client",
			in:    Inputs{WS: ms(42), TCP: ms(41), ZeroTrace: ms(38), ZeroTraceReachedClient: true},
			label: LabelWs0TClient, diffMs: 4, verdict: VerdictDirect,
		},
		{
			name:  "direct, no ICMP, 0trace stopped in the client's network",
			in:    Inputs{WS: ms(42), TCP: ms(41), ZeroTrace: ms(36), ZeroTraceSameNetwork: true},
			label: LabelWs0TNetwork, diffMs: 6, verdict: VerdictDirect,
		},
		{
			name:  "0trace stopped elsewhere: best effort",
			in:    Inputs{WS: ms(120), TCP: ms(119), ZeroTrace: ms(20)},
			label: LabelBestEffortWs0T, diffMs: 100, verdict: VerdictInconclusive,
		},
		{
			name:  "SOCKS proxy: TCP and ICMP both end at the proxy",
			in:    Inputs{WS: ms(300), TCP: ms(30), ICMP: ms(29)},
			label: LabelE2EWsTCPICMP, diffMs: 271, verdict: VerdictProxy,
		},
		{
			name:  "SOCKS proxy: TCP matches 0trace",
			in:    Inputs{WS: ms(300), TCP: ms(30), ZeroTrace: ms(33)},
			label: LabelE2EWsTCP0T, diffMs: 270, verdict: VerdictProxy,
		},
		{
			name:  "TCP faster than WS but nothing else matches: best effort",
			in:    Inputs{WS: ms(300), TCP: ms(30)},
			label: LabelE2EBestEffortWsTCP, diffMs: 270, verdict: VerdictInconclusive,
		},
		{
			name:  "no WebSocket samples",
			in:    Inputs{TCP: ms(30), ICMP: ms(30)},
			label: LabelNoData, verdict: VerdictInconclusive,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Decide(c.in, threshold)
			if d.Label != c.label {
				t.Errorf("label = %s, want %s", d.Label, c.label)
			}
			if c.label != LabelNoData && d.Diff != time.Duration(c.diffMs)*time.Millisecond {
				t.Errorf("diff = %v, want %dms", d.Diff, c.diffMs)
			}
			if d.Verdict != c.verdict {
				t.Errorf("verdict = %s, want %s", d.Verdict, c.verdict)
			}
		})
	}
}

func TestMaxDistanceKm(t *testing.T) {
	// 100 ms of extra RTT allows at most ~6,660 km between visitor and proxy.
	got := maxDistanceKm(100 * time.Millisecond)
	if got < 6600 || got > 6700 {
		t.Fatalf("maxDistanceKm(100ms) = %.0f", got)
	}
}
