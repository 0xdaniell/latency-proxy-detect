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
  return ms == null ? "no answer" : `${ms.toFixed(1)} ms`;
}

function setVerdict(state, title, detail) {
  $("verdict").dataset.state = state;
  $("verdict-title").textContent = title;
  $("verdict-detail").textContent = detail;
}

function showResult(r) {
  $("progress").hidden = true;
  const diff = r.diffMs;
  if (r.verdict === "proxy") {
    const km = r.maxDistanceKm ? ` The browser is up to about ${Math.round(r.maxDistanceKm).toLocaleString()} km from the address it connects from.` : "";
    setVerdict("proxy", "VPN or proxy detected",
      `Your browser answered ${diff.toFixed(0)} ms later than your IP address did.${km}`);
  } else if (r.verdict === "direct") {
    setVerdict("direct", "No distant VPN or proxy seen",
      `Your browser and your IP address answered within ${Math.max(diff, 0).toFixed(0)} ms of each other. A VPN server close to you would also look like this.`);
  } else {
    setVerdict("inconclusive", "Inconclusive",
      "Your network did not answer enough probes for a reliable verdict. Measuring again often helps.");
  }

  const t = r.rtt;
  $("r-ws").textContent = `${fmt(t.webSocketMs)} · ${t.webSocketSamples} replies`;
  $("r-tcp").textContent = fmt(t.tcpHandshakeMs);
  $("r-icmp").textContent = fmt(t.icmpMs);
  $("r-zt").textContent = fmt(t.zeroTraceMs);
  $("r-zt-note").textContent = t.zeroTraceMs == null
    ? "Network layer: no hop answered."
    : t.zeroTraceReachedClient
      ? `Network layer: reached your IP address (hop ${t.zeroTraceHopTTL}).`
      : `Network layer: farthest answer from ${t.zeroTraceHop} (hop ${t.zeroTraceHopTTL})${t.zeroTraceSameNetwork ? ", inside your network" : ""}.`;
  $("r-diff").textContent = diff == null ? "–" : `${diff.toFixed(1)} ms`;
  $("r-threshold").textContent = r.thresholdMs;
  $("r-label").textContent = r.label;
  $("r-ip").textContent = `Measured address: ${r.ip}`;
  $("numbers").hidden = false;
  $("again").disabled = false;
}

async function fetchResult(id) {
  // 0trace can break the WebSocket's TCP connection. The result is then
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

function measure() {
  $("again").disabled = true;
  $("numbers").hidden = true;
  const bar = $("progress");
  bar.hidden = false;
  bar.value = 0;
  setVerdict("running", "Measuring…", "Timing your browser and your IP address.");

  let id = null;
  let total = 100;
  let got = 0;
  let done = false;

  const ws = new WebSocket(wsURL());
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
        bar.value = Math.min(80, (got / total) * 80);
        break;
      case "status":
        bar.value = 85;
        setVerdict("running", "Measuring…", "Tracing the route to your IP address.");
        break;
      case "result":
        done = true;
        showResult(msg.result);
        break;
      case "error":
        done = true;
        bar.hidden = true;
        setVerdict("inconclusive", "Could not measure", msg.error);
        $("again").disabled = false;
        $("numbers").hidden = true;
        break;
    }
  };
  ws.onclose = async () => {
    if (done) return;
    if (!id) {
      bar.hidden = true;
      setVerdict("inconclusive", "Could not reach the server", "The measurement server did not answer. It may be down, or a firewall blocks WebSockets.");
      $("again").disabled = false;
      return;
    }
    const r = await fetchResult(id);
    if (r) showResult(r);
    else {
      bar.hidden = true;
      setVerdict("inconclusive", "Lost the connection", "The measurement did not finish. Try again.");
      $("again").disabled = false;
    }
  };
}

$("again").addEventListener("click", measure);
if (window.LPD_SOURCE) $("source-link").href = window.LPD_SOURCE;
measure();
