package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

// The TCP handshake RTT and the raw *net.TCPConn (which 0trace needs) must
// reach the handler through TLS, as they do in production.
func TestHandshakeInfoReachesHandlerUnderTLS(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(handshakeListener{ln}, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})

	type seen struct {
		rtt     *time.Duration
		tcpConn bool
	}
	got := make(chan seen, 1)
	srv := &http.Server{
		ConnContext: connContext,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hc, ok := r.Context().Value(connCtxKey{}).(*handshakeConn)
			if !ok {
				got <- seen{}
				return
			}
			_, isTCP := hc.Conn.(*net.TCPConn)
			got <- seen{rtt: hc.handshakeRTT, tcpConn: isTCP}
		}),
	}
	go srv.Serve(tlsLn)
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	s := <-got
	if s.rtt == nil || *s.rtt <= 0 {
		t.Errorf("handshake RTT missing under TLS: %v", s.rtt)
	}
	if !s.tcpConn {
		t.Error("handler cannot reach the *net.TCPConn under TLS")
	}
}
