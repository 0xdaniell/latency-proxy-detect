# latency-proxy-detect

A web page that tells visitors whether they reach it through a **distant VPN or proxy**. It looks only at network latency: no IP reputation lists, no geolocation database, no cookies.

It is an independent, self-hostable implementation of the method in
**[CalcuLatency: Leveraging Cross-Layer Network Latency Measurements to Detect Proxy-Enabled Abuse](https://www.usenix.org/conference/usenixsecurity24/presentation/ramesh)**
(Ramesh, Winter, Korman, Ensafi, USENIX Security 2024). The paper's authors released [evaluation scripts](https://github.com/censoredplanet/calculatency-code) and the [zerotrace](https://github.com/brave/zerotrace) library, but no ready-to-run service. This project is that service.

## How it works

A visitor opens the page. The server then measures four round trip times:

| Layer | Measurement | Who answers |
|---|---|---|
| Application | 100 WebSocket echoes, each with a random nonce, so the browser can't answer early | the visitor's **browser** |
| Transport | the TCP handshake (SYN/ACK → ACK), read from the kernel's `TCP_INFO` | whatever opened the TCP connection |
| Network | 5 ICMP echo requests to the connecting IP | the **IP address** the visitor connects from |
| Network | **0trace**: a traceroute sent *inside* the already-open TCP connection, so it passes NAT and stateful firewalls | the IP address, or the last hop before it |

On a direct connection, the browser and the IP address are the same machine (or the same home network), so all the RTTs agree. Through a VPN, the network-layer probes stop at the VPN server, while the WebSocket echoes travel on to the browser. The decision tree from the paper (Figure 6) picks the right pair of RTTs. A difference above **50 ms** is reported as a VPN or proxy. The difference also bounds the visitor-to-proxy distance: at most about 66 km per millisecond.

The paper's evaluation (about 1,200 measurements from 37 countries) found:
- 0.95% false positives;
- 2.9% false negatives for proxies more than about 1,000 km (650 miles) from the user.

### Limits

- A VPN server near the visitor (within roughly 1,000 km) usually looks like a direct connection.
- A browser that itself runs on a remote machine (a remote desktop, a VPS) is not detected. The whole path ends there.
- Someone who controls the proxy can delay their own replies. [Ali et al. (NDSS 2026)](https://www.ndss-symposium.org/wp-content/uploads/2026-f2086-paper.pdf) show that traffic scheduling defeats RTT-discrepancy detectors. This tool catches ordinary VPN and proxy use, not a determined adversary.
- Only IPv4 visitors are measured, because 0trace is IPv4-only.
- Treat the result as one signal, not proof.

### Differences from the original zerotrace

`internal/zerotrace` is a modified copy of [brave/zerotrace](https://github.com/brave/zerotrace) (MPL-2.0). The original sends its probes with sequence number 0 and a 12-byte payload. In our test lab, a Linux NAT router (iptables MASQUERADE) neither forwarded those probes nor answered them with ICMP, so 0trace got no reply at all. Linux connection tracking probably marks them as out of window. With the change below, the same lab reached the client on every run:
- **Probes are pure ACKs that carry the connection's real sequence and acknowledgement numbers.** These come from the captured SYN/ACK plus `TCP_INFO`. The NAT router forwards them, and the client should discard them as duplicate ACKs. In our tests the WebSocket stayed usable after 0trace.
- The result includes the farthest hop's address, and whether that hop is the client itself.
- A nil-pointer panic is fixed, and so is a send-on-closed-channel race.

## Run it

The server must receive visitors' TCP connections **directly**. A CDN, a reverse proxy (nginx, Caddy), a load balancer or a tunnel in front of it would be measured instead of the visitor. It also needs raw sockets (`NET_RAW`, `NET_ADMIN`), so serverless hosts (Vercel, Netlify, Cloud Run) cannot run it. Any VM with a public IPv4 address works.

### Free: Google Cloud e2-micro + GitHub Pages

Google Cloud's free tier includes one e2-micro VM in `us-west1`, `us-central1` or `us-east1`, with a standard persistent disk of up to 30 GB. Check [Google's current free-tier terms](https://cloud.google.com/free/docs/free-cloud-features#compute) and set a budget alert. Google has charged for external IPv4 addresses since 2024, and whether that charge is waived for a free-tier VM can change.

With the [gcloud CLI](https://cloud.google.com/sdk/docs/install), run:

```sh
OWNER=your-github-name          # the account or organisation hosting this repository, in lower case
ZONE=us-central1-a
TOKEN=$(openssl rand -hex 24)   # admin token; keep it

gcloud compute firewall-rules create lpd-web --allow=tcp:80,tcp:443 --target-tags=lpd
gcloud compute firewall-rules create lpd-icmp --allow=icmp --target-tags=lpd   # 0trace and ping replies

gcloud compute instances create lpd --zone=$ZONE \
  --machine-type=e2-micro --boot-disk-type=pd-standard --boot-disk-size=10GB \
  --image-family=debian-12 --image-project=debian-cloud --tags=lpd \
  --metadata-from-file=startup-script=deploy/gce-startup.sh \
  --metadata=lpd-repo=https://github.com/$OWNER/latency-proxy-detect,lpd-admin-token=$TOKEN,lpd-allowed-origins=https://$OWNER.github.io,lpd-source-url=https://github.com/$OWNER/latency-proxy-detect

gcloud compute instances describe lpd --zone=$ZONE \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
```

The VM builds the server from the repository on first boot, which takes a few minutes. If the address is `34.56.78.90`, the server answers at `https://34-56-78-90.sslip.io`. [sslip.io](https://sslip.io) resolves that name to the IP, and the server fetches a Let's Encrypt certificate for it without a contact e-mail. Open that address: the server serves the page itself.

To also serve the page from GitHub Pages:
1. Under Settings → Pages, set the source to **GitHub Actions**.
2. Under Settings → Secrets and variables → Actions → Variables, add `LPD_SERVER_URL` = `https://34-56-78-90.sslip.io`.
3. Run the `pages` workflow.

The address changes if the VM is stopped and started. The startup script picks up the new one by itself; update `LPD_SERVER_URL` to match.

### Anywhere else with Docker

```sh
docker run -d --name lpd --restart unless-stopped \
  --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v /var/lib/lpd:/data \
  -e LPD_DOMAIN=your.domain.example \
  -e LPD_ADMIN_TOKEN=change-me \
  ghcr.io/OWNER/latency-proxy-detect:latest
```

Use `--network host`: Docker's port mapping is itself a proxy.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `LPD_DOMAIN` | – | Serve HTTPS on :443 (and ACME on :80) for this name, with a Let's Encrypt certificate |
| `LPD_HTTP_ADDR` | – | Serve plain HTTP on this address instead (testing) |
| `LPD_ALLOWED_ORIGINS` | – | Comma-separated origins allowed to use the server, e.g. a GitHub Pages site |
| `LPD_ADMIN_TOKEN` | – | Token for `/admin.html` and `/api/admin/visits`; admin is off when unset |
| `LPD_DATA_DIR` | `/data` | Where `visits.jsonl` and certificates are kept |
| `LPD_THRESHOLD` | `50ms` | RTT difference above which a visit counts as proxied |
| `LPD_PINGS` / `LPD_PING_INTERVAL` | `100` / `25ms` | WebSocket echoes and their spacing |
| `LPD_ICMP_COUNT` | `5` | ICMP echo requests |
| `LPD_ASN_LOOKUP` | `true` | Ask RIPEstat whether 0trace's last hop shares an AS with the visitor (only when ICMP fails and 0trace stops short) |
| `LPD_ANONYMIZE_IPS` | `false` | Store and show addresses with the last octet zeroed |
| `LPD_MAX_CONCURRENT` | `8` | Measurements at once (one per visitor IP) |
| `LPD_IFACE` | `auto` | Interface for packet capture; `auto` uses the default route's |
| `LPD_SOURCE_URL` | – | Source-code link shown on the page |

## Results and the log

The visitor sees the verdict, the four RTTs, the difference and the decision-tree rule. Every measurement is appended to `visits.jsonl` with these fields:
- time;
- IP address;
- verdict and rule;
- all RTTs, and the 0trace hop;
- user agent.

`/admin.html` shows the most recent visits after you enter the admin token. Tell your visitors what you log. The page's footer does this by default.

## Develop

```sh
docker build -t latency-proxy-detect .    # runs the tests, then builds
```

The tests cover the decision tree. The whole measurement path was checked in a Docker lab, with a Linux NAT router between server and client and `tc netem` adding delay behind it:

| Scenario | Ping | Expected verdict |
|---|---|---|
| Client directly behind the NAT router | answered | direct |
| Client directly behind the NAT router | blocked, so 0trace is used | direct |
| Client 80 ms behind the router, like a distant VPN | answered | proxy |
| Client 80 ms behind the router, like a distant VPN | blocked | proxy |
| Client behind two routers, 20 ms away | answered | direct; 0trace reaches the client's address at hop 2 |

These are lab results. Real VPNs and real home routers may behave differently.

## License

MIT. `internal/zerotrace/` is MPL-2.0 (derived from brave/zerotrace).

This project is not affiliated with the paper's authors.

---

### בעברית בקצרה

דף אינטרנט שבודק אם המבקר מגיע דרך VPN או proxy רחוק. הבדיקה לא משתמשת ברשימות IP. היא משווה בין זמן ההלוך-חזור לדפדפן לבין זמן ההלוך-חזור לכתובת ה-IP, לפי המאמר CalcuLatency (USENIX Security 2024).

השרת חייב לרוץ על מכונה עם כתובת IP ציבורית, בלי שום שכבה באמצע. מכונת e2-micro החינמית של Google Cloud מתאימה. הדף עצמו יכול לשבת ב-GitHub Pages. הוראות ההתקנה נמצאות למעלה.
