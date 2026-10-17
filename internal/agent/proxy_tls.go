package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

// Terminate only the local CONNECT side. Upstream remains a separate fixed-IP
// connection with its normal policy checks. HTTP/2/opaque tunnels are never
// enabled: every inner HTTP/1 request must pass the same scope/admission handler.
func serveProxyTLS(ctx context.Context, w http.ResponseWriter, request *http.Request, host string, handler http.Handler, track func(net.Conn, bool)) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		cert.IPAddresses = []net.IP{ip}
	} else {
		cert.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return err
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("HTTP proxy does not support CONNECT hijacking")
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		return err
	}
	defer connection.Close()
	track(connection, true)
	defer track(connection, false)
	if _, err = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	// Preserve any TLS bytes already buffered by the HTTP server.
	client := tls.Server(&bufferedProxyConn{Conn: connection, reader: buffered.Reader}, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	handshakeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	err = client.HandshakeContext(handshakeCtx)
	cancel()
	if err != nil {
		return err
	}
	conn := &closingProxyConn{Conn: client, done: make(chan struct{})}
	listener := &proxyTLSListener{conn: conn}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 8 * time.Second, MaxHeaderBytes: 32 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	err = server.Serve(listener)
	if err != nil && err != net.ErrClosed && err != http.ErrServerClosed {
		return err
	}
	return nil
}

type bufferedProxyConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedProxyConn) Read(data []byte) (int, error) { return c.reader.Read(data) }

type closingProxyConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closingProxyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

type proxyTLSListener struct {
	conn     *closingProxyConn
	accepted bool
}

func (l *proxyTLSListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.conn.done
	return nil, net.ErrClosed
}
func (l *proxyTLSListener) Close() error   { return l.conn.Close() }
func (l *proxyTLSListener) Addr() net.Addr { return l.conn.LocalAddr() }
