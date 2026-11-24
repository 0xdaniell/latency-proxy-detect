// Command latency-proxy-detect serves a page that tells visitors whether they
// reach it through a distant VPN or proxy, by comparing application-layer and
// network-layer round trip times (the CalcuLatency method, USENIX Security
// 2024).
package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"latency-proxy-detect/internal/zerotrace"
)

//go:embed web
var webFS embed.FS

type config struct {
	domain         string
	httpAddr       string
	dataDir        string
	adminToken     string
	allowedOrigins map[string]bool
	iface          string
	pings          int
	pingInterval   time.Duration
	icmpCount      int
	threshold      time.Duration
	maxConcurrent  int
	asnLookup      bool
	anonymize      bool
	sourceURL      string
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	n, err := strconv.Atoi(env(key, strconv.Itoa(def)))
	if err != nil || n <= 0 {
		log.Fatalf("%s must be a positive integer", key)
	}
	return n
}

func envDur(key string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(env(key, def.String()))
	if err != nil || d <= 0 {
		log.Fatalf("%s must be a positive duration such as 50ms", key)
	}
	return d
}

func envBool(key string, def bool) bool {
	b, err := strconv.ParseBool(env(key, strconv.FormatBool(def)))
	if err != nil {
		log.Fatalf("%s must be true or false", key)
	}
	return b
}

func loadConfig() *config {
	c := &config{
		domain:         env("LPD_DOMAIN", ""),
		httpAddr:       env("LPD_HTTP_ADDR", ""),
		dataDir:        env("LPD_DATA_DIR", "/data"),
		adminToken:     env("LPD_ADMIN_TOKEN", ""),
		allowedOrigins: map[string]bool{},
		iface:          env("LPD_IFACE", "auto"),
		pings:          envInt("LPD_PINGS", 100),
		pingInterval:   envDur("LPD_PING_INTERVAL", 25*time.Millisecond),
		icmpCount:      envInt("LPD_ICMP_COUNT", 5),
		threshold:      envDur("LPD_THRESHOLD", 50*time.Millisecond),
		maxConcurrent:  envInt("LPD_MAX_CONCURRENT", 8),
		asnLookup:      envBool("LPD_ASN_LOOKUP", true),
		anonymize:      envBool("LPD_ANONYMIZE_IPS", false),
		sourceURL:      env("LPD_SOURCE_URL", ""),
	}
	for _, o := range strings.Split(env("LPD_ALLOWED_ORIGINS", ""), ",") {
		// Browsers send the Origin host in lower case.
		if o = strings.ToLower(strings.TrimRight(strings.TrimSpace(o), "/")); o != "" {
			c.allowedOrigins[o] = true
		}
	}
	if c.domain == "" && c.httpAddr == "" {
		log.Fatal("set LPD_DOMAIN (HTTPS with a free Let's Encrypt certificate) or LPD_HTTP_ADDR (plain HTTP, for testing)")
	}
	return c
}

// originAllowed accepts same-origin pages, the configured origins (such as a
// GitHub Pages site) and non-browser clients that send no Origin header.
func (c *config) originAllowed(r *http.Request) bool {
	origin := strings.ToLower(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	if c.allowedOrigins[origin] {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func (c *config) displayIP(ip net.IP) string {
	if c.anonymize {
		v4 := ip.To4()
		return net.IPv4(v4[0], v4[1], v4[2], 0).String()
	}
	return ip.String()
}

func (c *config) cors(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && c.allowedOrigins[strings.ToLower(origin)] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Headers", "Authorization")
		w.Header().Set("Vary", "Origin")
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func routes(c *config, m *measurer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws", m.handleWS)

	mux.HandleFunc("GET /api/result/{id}", func(w http.ResponseWriter, r *http.Request) {
		c.cors(w, r)
		if res := m.store.result(r.PathValue("id")); res != nil {
			writeJSON(w, http.StatusOK, res)
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})

	mux.HandleFunc("OPTIONS /api/", func(w http.ResponseWriter, r *http.Request) {
		c.cors(w, r)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /api/admin/visits", func(w http.ResponseWriter, r *http.Request) {
		c.cors(w, r)
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if c.adminToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(c.adminToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 1000 {
			limit = 200
		}
		writeJSON(w, http.StatusOK, m.store.latest(limit))
	})

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "zerotrace": m.zt != nil})
	})

	// The same static site that GitHub Pages serves. Here config.js points at
	// this server itself.
	mux.HandleFunc("GET /config.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		w.Header().Set("Cache-Control", "no-store")
		src, _ := json.Marshal(c.sourceURL)
		_, _ = w.Write([]byte("window.LPD_SERVER = \"\";\nwindow.LPD_SOURCE = " + string(src) + ";\n"))
	})
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))

	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

// connContext makes the accepted connection (and its handshake RTT) available
// to handlers, under TLS or not.
func connContext(ctx context.Context, conn net.Conn) context.Context {
	if tc, ok := conn.(*tls.Conn); ok {
		conn = tc.NetConn()
	}
	if hc, ok := conn.(*handshakeConn); ok {
		return context.WithValue(ctx, connCtxKey{}, hc)
	}
	return ctx
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	c := loadConfig()

	st, err := openStore(c.dataDir, 1000)
	if err != nil {
		log.Fatalf("data dir: %v", err)
	}

	p, err := newPinger()
	if err != nil {
		log.Fatalf("ICMP needs the NET_RAW capability: %v", err)
	}

	iface := c.iface
	if iface == "auto" {
		if iface, err = defaultInterface(); err != nil {
			log.Fatalf("network interface: %v (set LPD_IFACE)", err)
		}
	}
	ztCfg := zerotrace.NewDefaultConfig()
	ztCfg.Interface = iface
	zt := zerotrace.NewZeroTrace(ztCfg)
	if err := zt.Start(); err != nil {
		log.Printf("0trace disabled (needs NET_RAW and NET_ADMIN, and libpcap): %v", err)
		zt = nil
	}

	m := &measurer{cfg: c, zt: zt, pinger: p, store: st, slots: make(chan struct{}, c.maxConcurrent), active: map[string]bool{}}
	if c.asnLookup {
		m.asn = newASNLookup()
	}

	srv := &http.Server{
		Handler:           routes(c, m),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		// HTTP/1.1 only: every WebSocket must get its own TCP connection,
		// because the TCP handshake RTT and 0trace are measured per connection.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ConnContext:  connContext,
	}

	listen := func(addr string) net.Listener {
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			log.Fatalf("listen %s: %v", addr, err)
		}
		return handshakeListener{ln}
	}

	if c.domain == "" {
		log.Printf("serving plain HTTP on %s (interface %s, 0trace %v)", c.httpAddr, iface, zt != nil)
		log.Fatal(srv.Serve(listen(c.httpAddr)))
	}

	// HTTPS with a Let's Encrypt certificate. No contact e-mail is sent.
	cm := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(c.dataDir + "/certs"),
		HostPolicy: autocert.HostWhitelist(c.domain),
	}
	tlsCfg := cm.TLSConfig()
	tlsCfg.NextProtos = []string{"http/1.1", "acme-tls/1"}
	tlsCfg.MinVersion = tls.VersionTLS12

	go func() {
		// Port 80: ACME http-01 challenges and a redirect to HTTPS.
		log.Fatal(http.Serve(listen(":80"), cm.HTTPHandler(nil)))
	}()
	log.Printf("serving https://%s (interface %s, 0trace %v)", c.domain, iface, zt != nil)
	log.Fatal(srv.Serve(tls.NewListener(listen(":443"), tlsCfg)))
}
