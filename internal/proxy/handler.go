package proxy

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/archellir/sekisho/internal/config"
)

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

type ProxyHandler struct {
	config    *config.Config
	transport http.RoundTripper
	upstreams map[string]*url.URL
}

func NewProxyHandler(cfg *config.Config, transport http.RoundTripper) *ProxyHandler {
	upstreams := make(map[string]*url.URL)
	for _, upstream := range cfg.Upstream {
		if target, err := url.Parse(upstream.Target); err == nil {
			upstreams[upstream.Host] = target
		}
	}

	return &ProxyHandler{
		config:    cfg,
		transport: transport,
		upstreams: upstreams,
	}
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleTunnel(w, r)
		return
	}

	target := p.selectUpstream(r.Host, r.URL.Path)
	if target == nil {
		http.Error(w, "No upstream target found", http.StatusBadGateway)
		return
	}

	p.proxyRequest(w, r, target)
}

func (p *ProxyHandler) selectUpstream(host, path string) *url.URL {
	if target, ok := p.upstreams[host]; ok {
		return target
	}

	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
		if target, ok := p.upstreams[host]; ok {
			return target
		}
	}

	for hostPattern, target := range p.upstreams {
		if matchHost(hostPattern, host) {
			return target
		}
	}

	return nil
}

func (p *ProxyHandler) proxyRequest(w http.ResponseWriter, r *http.Request, target *url.URL) {
	outReq := p.buildRequest(r, target)

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	p.copyResponse(w, resp)
}

func (p *ProxyHandler) buildRequest(r *http.Request, target *url.URL) *http.Request {
	outReq := &http.Request{
		Method: r.Method,
		URL: &url.URL{
			Scheme:   target.Scheme,
			Host:     target.Host,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
		},
		Proto:      r.Proto,
		ProtoMajor: r.ProtoMajor,
		ProtoMinor: r.ProtoMinor,
		Header:     make(http.Header),
		Body:       r.Body,
		Host:       target.Host,
	}

	if r.ContentLength > 0 {
		outReq.ContentLength = r.ContentLength
	}

	for name, values := range r.Header {
		if !isHopHeader(name) {
			for _, value := range values {
				outReq.Header.Add(name, value)
			}
		}
	}

	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if prior := outReq.Header.Get("X-Forwarded-For"); prior != "" {
			clientIP = prior + ", " + clientIP
		}
		outReq.Header.Set("X-Forwarded-For", clientIP)
	}

	outReq.Header.Set("X-Forwarded-Proto", "https")
	outReq.Header.Set("X-Forwarded-Host", r.Host)

	return outReq
}

func (p *ProxyHandler) copyResponse(w http.ResponseWriter, resp *http.Response) {
	for name, values := range resp.Header {
		if !isHopHeader(name) {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
	}

	w.WriteHeader(resp.StatusCode)

	if resp.ContentLength > 0 {
		io.CopyN(w, resp.Body, resp.ContentLength)
	} else {
		io.Copy(w, resp.Body)
	}
}

func (p *ProxyHandler) handleTunnel(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	go p.transfer(destConn, clientConn)
	go p.transfer(clientConn, destConn)
}

func (p *ProxyHandler) transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func isHopHeader(header string) bool {
	for _, h := range hopHeaders {
		if strings.EqualFold(h, header) {
			return true
		}
	}
	return false
}

func matchHost(pattern, host string) bool {
	if pattern == host {
		return true
	}
	
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return strings.HasSuffix(host, suffix)
	}
	
	return false
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func appendHostToXForwardHeader(header http.Header, host string) {
	if prior := header.Get("X-Forwarded-For"); prior != "" {
		host = prior + ", " + host
	}
	header.Set("X-Forwarded-For", host)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func removeConnectionHeaders(h http.Header) {
	for _, f := range h["Connection"] {
		for _, sf := range strings.Split(f, ",") {
			if sf = strings.TrimSpace(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
}