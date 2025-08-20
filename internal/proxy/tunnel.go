package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type TunnelHandler struct {
	allowedHosts map[string]bool
	timeout      time.Duration
}

func NewTunnelHandler(allowedHosts []string, timeout time.Duration) *TunnelHandler {
	hosts := make(map[string]bool)
	for _, host := range allowedHosts {
		hosts[host] = true
	}
	
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &TunnelHandler{
		allowedHosts: hosts,
		timeout:      timeout,
	}
}

func (t *TunnelHandler) HandleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	if len(t.allowedHosts) > 0 && !t.allowedHosts[host] {
		http.Error(w, "Host not allowed", http.StatusForbidden)
		return
	}

	destConn, err := net.DialTimeout("tcp", r.Host, t.timeout)
	if err != nil {
		http.Error(w, fmt.Sprintf("Cannot reach destination server: %v", err), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, bufrw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("Cannot hijack connection: %v", err), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	if _, err := bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := bufrw.Flush(); err != nil {
		return
	}

	errCh := make(chan error, 2)
	
	go func() {
		defer destConn.Close()
		defer clientConn.Close()
		_, err := io.Copy(destConn, clientConn)
		errCh <- err
	}()

	go func() {
		defer destConn.Close() 
		defer clientConn.Close()
		_, err := io.Copy(clientConn, destConn)
		errCh <- err
	}()

	<-errCh
}

type ConnectDialer struct {
	proxyURL *net.TCPAddr
}

func NewConnectDialer(proxyAddr string) (*ConnectDialer, error) {
	addr, err := net.ResolveTCPAddr("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	
	return &ConnectDialer{proxyURL: addr}, nil
}

func (cd *ConnectDialer) Dial(network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}

	conn, err := net.DialTCP("tcp", nil, cd.proxyURL)
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: "CONNECT",
		URL:    nil,
		Host:   addr,
		Header: make(http.Header),
	}

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("CONNECT failed: %s", resp.Status)
	}

	return conn, nil
}

func ProxyTunnel(w http.ResponseWriter, r *http.Request, proxyURL string) {
	if r.Method != http.MethodConnect {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dialer, err := NewConnectDialer(proxyURL)
	if err != nil {
		http.Error(w, "Invalid proxy URL", http.StatusInternalServerError)
		return
	}

	destConn, err := dialer.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, bufrw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	if _, err := bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := bufrw.Flush(); err != nil {
		return
	}

	go io.Copy(destConn, clientConn)
	io.Copy(clientConn, destConn)
}