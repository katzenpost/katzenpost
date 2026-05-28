// addr.go - Address validation and utilities.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package utils

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Transport scheme names recognised by EnsureURLAddrIPPort. These
// mirror the constants in core/pki but are duplicated here to keep
// core/utils free of an import cycle with that package.
const (
	transportTCP   = "tcp"
	transportTCPv4 = "tcp4"
	transportTCPv6 = "tcp6"
	transportQUIC  = "quic"
	transportOnion = "onion"
)

var unsuitableNetworks []*net.IPNet

// EnsureAddrIPPort returns nil iff the address is a raw IP + Port combination.
func EnsureAddrIPPort(a string) error {
	host, _, err := net.SplitHostPort(a)
	if err != nil {
		return err
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("address '%v' is not an IP", host)
	}
	return nil
}

// EnsureURLAddrIPPort returns nil iff addr is a URL of the form
// `<scheme>://host:port` whose host portion is a literal IPv4 or
// IPv6 address and whose port is present. The onion:// scheme is
// always accepted because .onion addresses are resolved by Tor's
// local proxy, not by the system DNS resolver. All other recognised
// schemes (tcp, tcp4, tcp6, quic) must carry an IP literal so that
// the daemon does not perform a DNS lookup at dial time. Used by
// daemon config validators to refuse hostname addresses in
// production deployments where DNS is not part of the trust base.
func EnsureURLAddrIPPort(addr string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("address %q is not a valid URL: %w", addr, err)
	}
	switch strings.ToLower(u.Scheme) {
	case transportOnion:
		return nil
	case transportTCP, transportTCPv4, transportTCPv6, transportQUIC:
	default:
		return fmt.Errorf("address %q has unrecognised scheme %q", addr, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("address %q has no host portion", addr)
	}
	if u.Port() == "" {
		return fmt.Errorf("address %q has no port", addr)
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("address %q has hostname %q which is not an IP literal; production deployments must not rely on DNS resolution (set AllowHostnameAddresses=true to override for docker-mixnet testing)", addr, host)
	}
	return nil
}

// RejectDNSAddrs validates every URL in addrs by calling
// EnsureURLAddrIPPort, but only when allowHostnames is false. When
// allowHostnames is true (e.g. inside a docker-mixnet bridge
// network where service hostnames resolve via an embedded DNS
// runtime), the function returns nil without inspecting the
// addresses. This is the canonical entry point for daemon config
// validators: pass the operator-supplied flag together with the
// address slice.
func RejectDNSAddrs(addrs []string, allowHostnames bool) error {
	if allowHostnames {
		return nil
	}
	for _, a := range addrs {
		if err := EnsureURLAddrIPPort(a); err != nil {
			return err
		}
	}
	return nil
}

// RejectDNSMetricsAddr validates a plain `host:port` string (the
// shape MetricsAddress fields use; no scheme prefix). When
// allowHostnames is true the function returns nil unconditionally;
// otherwise the host portion must be a literal IPv4 or IPv6
// address and the port must be present.
func RejectDNSMetricsAddr(addr string, allowHostnames bool) error {
	if allowHostnames {
		return nil
	}
	if addr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("metrics address %q is not a valid host:port: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("metrics address %q has no port", addr)
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("metrics address %q has hostname %q which is not an IP literal; production deployments must not rely on DNS resolution", addr, host)
	}
	return nil
}

// GetExternalIPv4Address attempts to guess an external IPv4 address by
// interface enumeration.
func GetExternalIPv4Address() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

addrLoop:
	for _, addr := range addrs {
		if addr.Network() != "ip+net" {
			continue
		}

		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			return nil, err
		}

		for _, n := range unsuitableNetworks {
			if n.Contains(ip) {
				continue addrLoop
			}
		}

		if ip.To4() == nil {
			continue
		}

		return ip, nil
	}

	return nil, fmt.Errorf("no globally routable IPv4 addresses found")
}

func init() {
	for _, v := range []string{
		// Loopback addresses.
		"127.0.0.0/8",
		"::1/128",

		// Local addresses.
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",

		// Link-local addresses.
		"169.254.0.0/16",
		"fe80::/10",

		// Oddities.
		"::ffff:0:0/96", // IPv4 mapped addresses
		"64:ff9b::/96",  // IPv4/IPv6 translation

		// TODO: There's more things that could be on here.
	} {
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			panic("BUG: Failed to build unsuitable address list: " + err.Error())
		}
		unsuitableNetworks = append(unsuitableNetworks, n)
	}
}
