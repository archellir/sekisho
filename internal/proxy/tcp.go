package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/archellir/sekisho/internal/config"
)

type TCPProxy struct {
	config      *config.Config
	listeners   map[string]net.Listener
	connections map[string]*TCPConnection
	mutex       sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

type TCPConnection struct {
	ID         string
	ClientAddr string
	TargetAddr string
	StartTime  time.Time
	BytesSent  int64
	BytesRecv  int64
	Active     bool
}

type TCPAuthenticator interface {
	Authenticate(conn net.Conn, config *config.TCPProxyConfig) (bool, string, error)
}

func NewTCPProxy(cfg *config.Config) *TCPProxy {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &TCPProxy{
		config:      cfg,
		listeners:   make(map[string]net.Listener),
		connections: make(map[string]*TCPConnection),
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (p *TCPProxy) Start() error {
	for _, tcpConfig := range p.config.TCPProxy {
		if err := p.startListener(&tcpConfig); err != nil {
			return fmt.Errorf("failed to start TCP proxy for %s: %w", tcpConfig.Name, err)
		}
	}
	return nil
}

func (p *TCPProxy) startListener(tcpConfig *config.TCPProxyConfig) error {
	addr := fmt.Sprintf(":%d", tcpConfig.ListenPort)
	
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	p.mutex.Lock()
	p.listeners[tcpConfig.Name] = listener
	p.mutex.Unlock()

	go p.acceptConnections(listener, tcpConfig)
	return nil
}

func (p *TCPProxy) acceptConnections(listener net.Listener, tcpConfig *config.TCPProxyConfig) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return
			default:
				continue
			}
		}

		go p.handleConnection(conn, tcpConfig)
	}
}

func (p *TCPProxy) handleConnection(clientConn net.Conn, tcpConfig *config.TCPProxyConfig) {
	defer clientConn.Close()

	connID := generateConnectionID()
	connection := &TCPConnection{
		ID:         connID,
		ClientAddr: clientConn.RemoteAddr().String(),
		TargetAddr: tcpConfig.Target,
		StartTime:  time.Now(),
		Active:     true,
	}

	p.mutex.Lock()
	p.connections[connID] = connection
	p.mutex.Unlock()

	defer func() {
		p.mutex.Lock()
		if conn, exists := p.connections[connID]; exists {
			conn.Active = false
		}
		p.mutex.Unlock()
	}()

	if len(tcpConfig.AllowedUsers) > 0 {
		if !p.isConnectionAuthorized(clientConn, tcpConfig) {
			return
		}
	}

	targetConn, err := net.DialTimeout("tcp", tcpConfig.Target, 10*time.Second)
	if err != nil {
		return
	}
	defer targetConn.Close()

	p.proxyTraffic(clientConn, targetConn, connection)
}

func (p *TCPProxy) isConnectionAuthorized(conn net.Conn, tcpConfig *config.TCPProxyConfig) bool {
	clientIP := getConnectionIP(conn)
	
	for _, allowedIP := range tcpConfig.AllowedUsers {
		if clientIP == allowedIP {
			return true
		}
	}
	
	return false
}

func (p *TCPProxy) proxyTraffic(client, target net.Conn, connection *TCPConnection) {
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		n, _ := io.Copy(target, client)
		p.mutex.Lock()
		connection.BytesSent += n
		p.mutex.Unlock()
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		n, _ := io.Copy(client, target)
		p.mutex.Lock()
		connection.BytesRecv += n
		p.mutex.Unlock()
	}()

	<-done
}

func (p *TCPProxy) Stop() error {
	p.cancel()

	p.mutex.Lock()
	defer p.mutex.Unlock()

	var errors []error
	for name, listener := range p.listeners {
		if err := listener.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close listener %s: %w", name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors stopping TCP proxy: %v", errors)
	}

	return nil
}

func (p *TCPProxy) GetConnections() []*TCPConnection {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	connections := make([]*TCPConnection, 0, len(p.connections))
	for _, conn := range p.connections {
		connections = append(connections, conn)
	}

	return connections
}

func (p *TCPProxy) GetActiveConnections() []*TCPConnection {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	var active []*TCPConnection
	for _, conn := range p.connections {
		if conn.Active {
			active = append(active, conn)
		}
	}

	return active
}

func generateConnectionID() string {
	return fmt.Sprintf("tcp-%d", time.Now().UnixNano())
}

func getConnectionIP(conn net.Conn) string {
	if addr := conn.RemoteAddr(); addr != nil {
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			return tcpAddr.IP.String()
		}
	}
	return conn.RemoteAddr().String()
}

type TLSProxy struct {
	*TCPProxy
	tlsConfig *tls.Config
}

func NewTLSProxy(cfg *config.Config, tlsConfig *tls.Config) *TLSProxy {
	return &TLSProxy{
		TCPProxy:  NewTCPProxy(cfg),
		tlsConfig: tlsConfig,
	}
}

func (p *TLSProxy) startListener(tcpConfig *config.TCPProxyConfig) error {
	addr := fmt.Sprintf(":%d", tcpConfig.ListenPort)
	
	listener, err := tls.Listen("tcp", addr, p.tlsConfig)
	if err != nil {
		return err
	}

	p.mutex.Lock()
	p.listeners[tcpConfig.Name] = listener
	p.mutex.Unlock()

	go p.acceptConnections(listener, tcpConfig)
	return nil
}

type SNIProxy struct {
	*TCPProxy
	routes map[string]string
}

func NewSNIProxy(cfg *config.Config) *SNIProxy {
	routes := make(map[string]string)
	for _, tcpConfig := range cfg.TCPProxy {
		if tcpConfig.Name != "" {
			routes[tcpConfig.Name] = tcpConfig.Target
		}
	}

	return &SNIProxy{
		TCPProxy: NewTCPProxy(cfg),
		routes:   routes,
	}
}

func (p *SNIProxy) handleConnection(clientConn net.Conn, tcpConfig *config.TCPProxyConfig) {
	defer clientConn.Close()

	serverName, err := p.extractSNI(clientConn)
	if err != nil {
		return
	}

	target, exists := p.routes[serverName]
	if !exists {
		target = tcpConfig.Target
	}

	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer targetConn.Close()

	connID := generateConnectionID()
	connection := &TCPConnection{
		ID:         connID,
		ClientAddr: clientConn.RemoteAddr().String(),
		TargetAddr: target,
		StartTime:  time.Now(),
		Active:     true,
	}

	p.mutex.Lock()
	p.connections[connID] = connection
	p.mutex.Unlock()

	p.proxyTraffic(clientConn, targetConn, connection)
}

func (p *SNIProxy) extractSNI(conn net.Conn) (string, error) {
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	if n < 43 {
		return "", fmt.Errorf("TLS handshake too short")
	}

	if buffer[0] != 0x16 {
		return "", fmt.Errorf("not a TLS handshake")
	}

	sessionIDLength := int(buffer[43])
	if 44+sessionIDLength >= n {
		return "", fmt.Errorf("invalid session ID length")
	}

	pos := 44 + sessionIDLength
	cipherSuitesLength := int(buffer[pos])<<8 | int(buffer[pos+1])
	pos += 2 + cipherSuitesLength

	if pos >= n {
		return "", fmt.Errorf("invalid cipher suites")
	}

	compressionMethodsLength := int(buffer[pos])
	pos += 1 + compressionMethodsLength

	if pos+2 >= n {
		return "", fmt.Errorf("no extensions")
	}

	extensionsLength := int(buffer[pos])<<8 | int(buffer[pos+1])
	pos += 2

	for pos < n && extensionsLength > 0 {
		if pos+4 >= n {
			break
		}

		extensionType := int(buffer[pos])<<8 | int(buffer[pos+1])
		extensionLength := int(buffer[pos+2])<<8 | int(buffer[pos+3])
		pos += 4

		if extensionType == 0 {
			if pos+5 >= n {
				break
			}
			serverNameLength := int(buffer[pos+3])<<8 | int(buffer[pos+4])
			if pos+5+serverNameLength <= n {
				return string(buffer[pos+5 : pos+5+serverNameLength]), nil
			}
		}

		pos += extensionLength
		extensionsLength -= 4 + extensionLength
	}

	return "", fmt.Errorf("SNI not found")
}