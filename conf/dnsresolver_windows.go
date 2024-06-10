/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"fmt"
	"github.com/miekg/dns"
	//"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/services"
	"net"
	"time"
)

const dnsPort = "53"
const dnsServer = "223.5.5.5"

func resolveHostname(name string, port uint16) (resolvedEndpoint *Endpoint, err error) {
	maxTries := 10
	if services.StartedAtBoot() {
		maxTries *= 3
	}
	for i := 0; i < maxTries; i++ {
		if i > 0 {
			time.Sleep(time.Second * 4)
		}
		resolvedEndpoint, err = resolveHostnameOnce(name, port)
		if err == nil {
			return
		}
		return
	}
	return
}

func resolveHostnameOnce(name string, port uint16) (resolvedEndpoint *Endpoint, err error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, net.JoinHostPort(dnsServer, dnsPort))
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}
	if r != nil {
		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				return &Endpoint{Host: a.A.String(), Port: port}, nil
			}
		}
	}

	m.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	r, _, err = c.Exchange(m, net.JoinHostPort(dnsServer, dnsPort))
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}
	if r != nil {
		for _, ans := range r.Answer {
			if v6Addr, ok := ans.(*dns.AAAA); ok {
				// Check whether this is a Teredo address
				if v6Addr.AAAA[0] == 0x20 && v6Addr.AAAA[1] == 0x01 && v6Addr.AAAA[2] == 0x00 && v6Addr.AAAA[3] == 0x00 {
					v4Addr := net.IPv4(v6Addr.AAAA[12], v6Addr.AAAA[13], v6Addr.AAAA[14], v6Addr.AAAA[15])
					port := (uint16(v6Addr.AAAA[10]) << 8) | uint16(v6Addr.AAAA[11])
					return &Endpoint{Host: v4Addr.String(), Port: port}, nil
				}
				return &Endpoint{Host: v6Addr.AAAA.String(), Port: port}, nil
			}
		}
	}
	return nil, fmt.Errorf("no A or AAAA records found for %s", name)
}

func (config *Config) ResolveEndpoints() error {
	for i := range config.Peers {
		if config.Peers[i].Endpoint.IsEmpty() {
			continue
		}
		var err error
		resolvedEndpoint, err := resolveHostname(config.Peers[i].Endpoint.Host, config.Peers[i].Endpoint.Port)
		if err != nil || resolvedEndpoint == nil {
			return fmt.Errorf("failed to resolve endpoint: %w", err)
		}
		config.Peers[i].Endpoint = *resolvedEndpoint
	}
	return nil
}
