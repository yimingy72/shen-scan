package agent

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

type targetPolicy struct {
	allowPrivate bool
	controlHost  string
	controlPort  string
	resolver     *net.Resolver
}

func newTargetPolicy(controlURL string, allowPrivate bool) targetPolicy {
	u, _ := url.Parse(controlURL)
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return targetPolicy{allowPrivate: allowPrivate, controlHost: strings.TrimSuffix(strings.ToLower(u.Hostname()), "."), controlPort: port, resolver: net.DefaultResolver}
}

func (p targetPolicy) validateIP(ip netip.Addr) error {
	if !ip.IsValid() {
		return fmt.Errorf("invalid IP address")
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("address %s is not an allowed scan target", ip)
	}
	if ip == netip.MustParseAddr("100.100.100.200") || ip == netip.MustParseAddr("169.254.169.254") {
		return fmt.Errorf("metadata address %s is blocked", ip)
	}
	if !p.allowPrivate && (ip.IsLoopback() || ip.IsPrivate()) {
		return fmt.Errorf("private address %s is blocked", ip)
	}
	return nil
}

func (p targetPolicy) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return nil, fmt.Errorf("empty target host")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if err := p.validateIP(ip); err != nil {
			return nil, err
		}
		return []netip.Addr{ip}, nil
	}
	addrs, err := p.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	allowed := make([]netip.Addr, 0, len(addrs))
	for _, ip := range addrs {
		if p.validateIP(ip.Unmap()) == nil {
			allowed = append(allowed, ip.Unmap())
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("host %s resolved only to blocked addresses", host)
	}
	return allowed, nil
}

func (p targetPolicy) validateEndpoint(ctx context.Context, host, port string) error {
	if port != p.controlPort {
		return nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == p.controlHost {
		return fmt.Errorf("control-plane endpoint %s:%s is blocked", host, port)
	}
	targetIPs, err := p.resolve(ctx, host)
	if err != nil {
		return err
	}
	controlIPs, err := p.resolver.LookupNetIP(ctx, "ip", p.controlHost)
	if err != nil {
		return nil
	}
	for _, targetIP := range targetIPs {
		for _, controlIP := range controlIPs {
			if targetIP.Unmap() == controlIP.Unmap() {
				return fmt.Errorf("control-plane endpoint %s:%s is blocked", host, port)
			}
		}
	}
	return nil
}
