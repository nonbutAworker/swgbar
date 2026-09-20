package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

var (
	ErrPrivateScopeRejected  = errors.New("TARGET_INTRANET_REJECTED: private IP not allowed without explicit scope authorization")
	ErrIPv6NotSupportedV1    = errors.New("IPV6_OUT_OF_SCOPE: v1 supports IPv4 only")
	ErrProxyUnsupported      = errors.New("PROXY_UNSUPPORTED: proxy response not 2xx")
	ErrProxyAuthRequired     = errors.New("PROXY_AUTH_REQUIRED: proxy authentication required (HTTP 407)")
	ErrNoIPv4AddressFound    = errors.New("DNS_NO_A_RECORD: no IPv4 address resolved")
)

// IsPrivateOrReservedIP checks if an IP is loopback, link-local, RFC1918, or multicast/broadcast
func IsPrivateOrReservedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}
	// RFC 1918:
	// 10.0.0.0/8
	if ipv4[0] == 10 {
		return true
	}
	// 172.16.0.0/12
	if ipv4[0] == 172 && (ipv4[1] >= 16 && ipv4[1] <= 31) {
		return true
	}
	// 192.168.0.0/16
	if ipv4[0] == 192 && ipv4[1] == 168 {
		return true
	}
	// 100.64.0.0/10 (CGNAT)
	if ipv4[0] == 100 && (ipv4[1] >= 64 && ipv4[1] <= 127) {
		return true
	}
	// 169.254.0.0/16 (Link local)
	if ipv4[0] == 169 && ipv4[1] == 254 {
		return true
	}
	return false
}

// DialTargetIPv4 connects to host:port via IPv4, applying RFC1918 security checks and proxy routing
func DialTargetIPv4(ctx context.Context, host string, port int, routeType string, proxyEndpoint string, allowPrivate bool) (net.Conn, net.IP, error) {
	deadline, ok := ctx.Deadline()
	var timeout time.Duration
	if ok {
		timeout = time.Until(deadline)
	} else {
		timeout = 8 * time.Second
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: -1, // No keep-alive needed for probe
	}

	if routeType == "HTTP_CONNECT" && proxyEndpoint != "" {
		// Tunnel through HTTP CONNECT proxy
		proxyConn, err := dialer.DialContext(ctx, "tcp4", proxyEndpoint)
		if err != nil {
			return nil, nil, fmt.Errorf("dial proxy %s: %w", proxyEndpoint, err)
		}

		targetAddr := fmt.Sprintf("%s:%d", host, port)
		req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: SWGBar/1.0\r\nProxy-Connection: Keep-Alive\r\n\r\n", targetAddr, targetAddr)
		if _, err := proxyConn.Write([]byte(req)); err != nil {
			proxyConn.Close()
			return nil, nil, fmt.Errorf("write CONNECT: %w", err)
		}

		br := bufio.NewReader(proxyConn)
		resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if err != nil {
			proxyConn.Close()
			return nil, nil, fmt.Errorf("read CONNECT response: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusProxyAuthRequired {
			proxyConn.Close()
			return nil, nil, ErrProxyAuthRequired
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			proxyConn.Close()
			return nil, nil, fmt.Errorf("%w: status %d", ErrProxyUnsupported, resp.StatusCode)
		}

		return proxyConn, nil, nil
	}

	// DIRECT IPv4
	var targetIP net.IP
	if parsed := net.ParseIP(host); parsed != nil {
		if ipv4 := parsed.To4(); ipv4 != nil {
			targetIP = ipv4
		} else {
			return nil, nil, ErrIPv6NotSupportedV1
		}
	} else {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve %s: %w", host, err)
		}
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				targetIP = ipv4
				break
			}
		}
		if targetIP == nil {
			return nil, nil, ErrNoIPv4AddressFound
		}
	}

	// Scope check
	if IsPrivateOrReservedIP(targetIP) && !allowPrivate {
		return nil, targetIP, ErrPrivateScopeRejected
	}

	targetAddr := net.JoinHostPort(targetIP.String(), fmt.Sprintf("%d", port))
	conn, err := dialer.DialContext(ctx, "tcp4", targetAddr)
	if err != nil {
		return nil, targetIP, err
	}

	return conn, targetIP, nil
}
