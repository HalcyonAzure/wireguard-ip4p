/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"log"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/services"
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
	hints := windows.AddrinfoW{
		Family:   windows.AF_UNSPEC,
		Socktype: windows.SOCK_DGRAM,
		Protocol: windows.IPPROTO_IP,
	}
	var result *windows.AddrinfoW
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	err = windows.GetAddrInfoW(name16, nil, &hints, &result)
	if err != nil {
		return
	}
	if result == nil {
		err = windows.WSAHOST_NOT_FOUND
		return
	}
	defer windows.FreeAddrInfoW(result)
	var v6 netip.Addr
	for ; result != nil; result = result.Next {
		if result.Family != windows.AF_INET && result.Family != windows.AF_INET6 {
			continue
		}
		addr := (*winipcfg.RawSockaddrInet)(unsafe.Pointer(result.Addr)).Addr()
		if addr.Is4() {
			return addr.String(), nil
		} else if !v6.IsValid() && addr.Is6() {
			v6 = addr
		}
	}
	if v6.IsValid() {
		return v6.String(), nil
	}
	err = windows.WSAHOST_NOT_FOUND
	return
}

func resolveHostnameIP4P(name string) (*Endpoint, error) {
    hints := windows.AddrinfoW{
        Family:   windows.AF_UNSPEC,
        Socktype: windows.SOCK_DGRAM,
        Protocol: windows.IPPROTO_IP,
    }
    var result *windows.AddrinfoW
    name16, err := windows.UTF16PtrFromString(name)
    if err != nil {
        return nil, err
    }
    err = windows.GetAddrInfoW(name16, nil, &hints, &result)
    if err != nil {
        return nil, err
    }
    if result == nil {
        return nil, windows.WSAHOST_NOT_FOUND
    }
    defer windows.FreeAddrInfoW(result)

    // Loop through all results, looking specifically for IPv6 addresses that conform to IP4P encoding
    for ; result != nil; result = result.Next {
        if result.Family == windows.AF_INET6 {
            addr := (*winipcfg.RawSockaddrInet)(unsafe.Pointer(result.Addr)).Addr()
            if addr.Is6() {
                ipv6 := addr.As16()
                // Check if the address starts with 2001:0000
                if ipv6[0] == 0x20 && ipv6[1] == 0x01 && ipv6[2] == 0x00 && ipv6[3] == 0x00 {
                    // Extract IPv4 and port from the special IPv6 format
                    ipv4 := net.IPv4(ipv6[12], ipv6[13], ipv6[14], ipv6[15])
                    port := (uint16(ipv6[10]) << 8) + uint16(ipv6[11])
                    return &Endpoint{Host: ipv4.String(), Port: port}, nil
                }
            }
        }
    }
    return nil, windows.WSAHOST_NOT_FOUND // No suitable IPv6 format found
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
            config.Peers[i].Endpoint = *resolvedEndpoint
        } else {
            config.Peers[i].Endpoint.Host, err = resolveHostname(config.Peers[i].Endpoint.Host)
        }
		if err != nil {
			return err
		}
	}
	return nil
}
