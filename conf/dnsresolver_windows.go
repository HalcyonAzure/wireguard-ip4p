/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"fmt"
	"github.com/miekg/dns"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/services"
	"log"
	"net"
	"time"
)

func resolveHostname(name string) (resolvedIPString string, err error) {
	maxTries := 10
	if services.StartedAtBoot() {
		maxTries *= 3
	}
	for i := 0; i < maxTries; i++ {
		if i > 0 {
			time.Sleep(time.Second * 4)
		}
		resolvedIPString, err = resolveHostnameOnce(name)
		if err == nil {
			return
		}
		if err == windows.WSATRY_AGAIN {
			log.Printf("Temporary DNS error when resolving %s, so sleeping for 4 seconds", name)
			continue
		}
		if err == windows.WSAHOST_NOT_FOUND && services.StartedAtBoot() {
			log.Printf("Host not found when resolving %s at boot time, so sleeping for 4 seconds", name)
			continue
		}
		return
	}
	return
}

func resolveHostnameOnce(name string) (resolvedIPString string, err error) {
	// 设置固定的DNS服务器和端口号
	const dnsServer = "223.5.5.5"
	const dnsPort = "53" // 标准DNS端口

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true

	// 尝试解析A记录（IPv4）
	r, _, err := c.Exchange(m, net.JoinHostPort(dnsServer, dnsPort))
	if err != nil {
		return "", fmt.Errorf("DNS query failed: %w", err)
	}
	if r != nil {
		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				return a.A.String(), nil
			}
		}
	}

	// 如果没有找到A记录，尝试AAAA记录（IPv6）
	m.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	r, _, err = c.Exchange(m, net.JoinHostPort(dnsServer, dnsPort))
	if err != nil {
		return "", fmt.Errorf("DNS query failed: %w", err)
	}
	if r != nil {
		for _, ans := range r.Answer {
			if aaaa, ok := ans.(*dns.AAAA); ok {
				return aaaa.AAAA.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no A or AAAA records found for %s", name)
}

func resolveHostnameIP4P(name string) (*Endpoint, error) {
	// 设置固定的DNS服务器和端口号
	const dnsServer = "223.5.5.5"
	const dnsPort = "53" // 标准DNS端口

	c := new(dns.Client)
	m := new(dns.Msg)
	m.RecursionDesired = true

	// 端口为1234，直接尝试AAAA解析
	m.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	r, _, err := c.Exchange(m, net.JoinHostPort(dnsServer, dnsPort))
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}
	if r != nil {
		for _, ans := range r.Answer {
			if v6Addr, ok := ans.(*dns.AAAA); ok {
				// Check whether start with 2001:0000
				if v6Addr.AAAA[0] == 0x20 && v6Addr.AAAA[1] == 0x01 && v6Addr.AAAA[2] == 0x00 && v6Addr.AAAA[3] == 0x00 {
					v4Addr := net.IPv4(v6Addr.AAAA[12], v6Addr.AAAA[13], v6Addr.AAAA[14], v6Addr.AAAA[15])
					port := (uint16(v6Addr.AAAA[10]) << 8) | uint16(v6Addr.AAAA[11])
					return &Endpoint{Host: v4Addr.String(), Port: port}, nil
				}

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
		// if Endpoint's Port equl to 1234, then resolveHostnameIP4P will be called
		if config.Peers[i].Endpoint.Port == 1234 {
			var resolvedEndpoint *Endpoint
			resolvedEndpoint, err = resolveHostnameIP4P(config.Peers[i].Endpoint.Host)
			//config.Peers[i].Endpoint = *resolvedEndpoint
			if err != nil || resolvedEndpoint == nil {
				return err
			} else {
				config.Peers[i].Endpoint = *resolvedEndpoint
			}
		} else {
			config.Peers[i].Endpoint.Host, err = resolveHostname(config.Peers[i].Endpoint.Host)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
