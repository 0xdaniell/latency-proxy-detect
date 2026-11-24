"use strict";

// Where the measurement server lives. Empty means "this same origin".
// config.js sets it; on GitHub Pages it points at the server.
const SERVER = (window.LPD_SERVER || "").replace(/\/$/, "");

const $ = (id) => document.getElementById(id);

function wsURL() {
  const base = SERVER || window.location.origin;
  return base.replace(/^http/, "ws") + "/ws";
}

function fmt(ms) {
  if (ms == null) return "No answer";
  return ms < 10 ? `${ms.toFixed(1)} ms` : `${Math.round(ms)} ms`;
}

function setState(state, status, verdict, detail) {
  $("result").dataset.state = state;
  $("status-text").textContent = status;
  $("verdict").textContent = verdict;
  $("detail").textContent = detail;
}

function setProgress(p) {
  $("progress-fill").style.width = `${Math.max(0, Math.min(100, p))}%`;
}

// The network-layer RTT the verdict was compared against.
function networkRTT(r) {
  const t = r.rtt;
  switch (r.label) {
    case "WsICMP": return t.icmpMs;
    case "Ws0TClient": case "Ws0TNetwork": case "BestEffortWs0T": case "E2EWs0tClient": return t.zeroTraceMs;
    case "E2EWsTCPICMP": return Math.min(t.tcpHandshakeMs, t.icmpMs);
    case "E2EWsTCP0t": return Math.min(t.tcpHandshakeMs, t.zeroTraceMs);
    case "E2EBestEffortWsTCP": return t.tcpHandshakeMs;
    default: return null;
  }
}

function showBars(app, net) {
  const max = Math.max(app || 0, net || 0, 1);
  $("v-app").textContent = fmt(app);
  $("v-net").textContent = fmt(net);
  // Wait a frame so the bars grow from zero.
  requestAnimationFrame(() => {
    $("bar-app").style.width = app == null ? "0" : `${Math.max(2, (app / max) * 100)}%`;
    $("bar-net").style.width = net == null ? "0" : `${Math.max(2, (net / max) * 100)}%`;
  });
}

function showResult(r) {
  setProgress(100);
  const diff = r.diffMs;
  if (r.verdict === "proxy") {
    const km = r.maxDistanceKm ? ` Your browser could be up to ${(Math.round(r.maxDistanceKm / 100) * 100 || Math.round(r.maxDistanceKm)).toLocaleString("en-US")} km from the address you connect from.` : "";
    setState("proxy", "VPN or proxy detected", "Something sits between us.",
      `Your browser answered ${Math.round(diff)} ms later than your IP address.${km}`);
  } else if (r.verdict === "direct") {
    setState("direct", "No distant VPN or proxy", "It’s a direct line.",
      "Your browser and your IP address answered at the same time. A VPN server close to you would look the same.");
  } else {
    setState("inconclusive", "Inconclusive", "Not enough signal.",
      "Your network didn’t answer enough probes for a reliable verdict. Measuring again often helps.");
  }

  showBars(r.rtt.webSocketMs, networkRTT(r));
  if (diff != null) {
    $("v-diff").textContent = `${diff >= 0 ? "+" : "−"}${fmt(Math.abs(diff))}`;
    $("gap").hidden = false;
  }

  const t = r.rtt;
  $("r-ws").textContent = fmt(t.webSocketMs);
  $("r-tcp").textContent = fmt(t.tcpHandshakeMs);
  $("r-icmp").textContent = fmt(t.icmpMs);
  $("r-zt").textContent = fmt(t.zeroTraceMs);
  $("r-zt-note").textContent = t.zeroTraceMs == null
    ? "Network layer · no hop answered"
    : t.zeroTraceReachedClient
      ? `Network layer · reached your address at hop ${t.zeroTraceHopTTL}`
      : `Network layer · stopped at hop ${t.zeroTraceHopTTL}${t.zeroTraceSameNetwork ? ", inside your network" : ""}`;
  $("r-ip").textContent = `Measured ${r.ip}`;
  $("r-label").textContent = r.label;
  $("r-threshold").textContent = r.thresholdMs;
  $("toggle-details").hidden = false;
  $("again").disabled = false;
}

function fail(status, verdict, detail) {
  setState("inconclusive", status, verdict, detail);
  $("again").disabled = false;
}

async function fetchResult(id) {
  // If the WebSocket's connection dies during the last step, the result is
  // fetched over a fresh connection.
  for (let i = 0; i < 10; i++) {
    await new Promise((res) => setTimeout(res, 1000));
    try {
      const resp = await fetch(`${SERVER}/api/result/${encodeURIComponent(id)}`, { cache: "no-store" });
      if (resp.ok) return resp.json();
    } catch (_) { /* retry */ }
  }
  return null;
}

function reset() {
  setState("running", "Measuring", "Timing your connection…", "This takes about ten seconds. Keep the page open.");
  setProgress(0);
  $("again").disabled = true;
  $("gap").hidden = true;
  $("v-app").textContent = "—";
  $("v-net").textContent = "—";
  $("bar-app").style.width = "0";
  $("bar-net").style.width = "0";
}

function measure() {
  reset();
  let id = null;
  let total = 100;
  let got = 0;
  let done = false;

  let ws;
  try {
    ws = new WebSocket(wsURL());
  } catch (_) {
    fail("Unavailable", "Couldn’t reach the server.", "The measurement server isn’t configured.");
    return;
  }
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    switch (msg.type) {
      case "hello":
        id = msg.id;
        total = msg.pings || total;
        break;
      case "ping":
        // Echo at once, with the nonce: the server times this round trip.
        ws.send(JSON.stringify({ type: "pong", seq: msg.seq, nonce: msg.nonce }));
        got++;
        setProgress((got / total) * 70);
        break;
      case "status":
        setProgress(80);
        $("detail").textContent = "Tracing the route to your IP address.";
        break;
      case "result":
        done = true;
        showResult(msg.result);
        break;
      case "error":
        done = true;
        fail("Unavailable", "Couldn’t measure.", msg.error);
        break;
    }
  };
  ws.onclose = async () => {
    if (done) return;
    if (!id) {
      fail("Unavailable", "Couldn’t reach the server.", "It may be down, or a firewall on your network blocks WebSockets.");
      return;
    }
    const r = await fetchResult(id);
    if (r) showResult(r);
    else fail("Interrupted", "The measurement didn’t finish.", "Try again.");
  };
}

$("again").addEventListener("click", measure);
$("toggle-details").addEventListener("click", () => {
  const open = $("details").hidden;
  $("details").hidden = !open;
  $("toggle-details").setAttribute("aria-expanded", String(open));
  $("toggle-details").textContent = open ? "Hide measurements" : "Show all measurements";
});
if (window.LPD_SOURCE) $("source-link").href = window.LPD_SOURCE;
measure();
