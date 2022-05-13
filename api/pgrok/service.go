/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package pgrok

import (
	"fmt"

	"github.com/provideplatform/provide-go/common"
)

// Client is the pgrok tunnel client
type Client struct {
	Tunnels []*Tunnel
}

// Factory is the pgrok tunnel client factory
func Factory() (*Client, error) {
	return &Client{
		Tunnels: make([]*Tunnel, 0),
	}, nil
}

// TunnelFactory initializes a new pgrok client Tunnel
func (c *Client) TunnelFactory(name, localAddr string, serverAddr, protocol, jwt *string, shutdownFn func(*string)) (*Tunnel, error) {
	proto := pgrokDefaultTunnelProtocol
	if protocol != nil {
		proto = *protocol
	}

	tun := &Tunnel{
		Name:      &name,
		LocalAddr: &localAddr,
		Protocol:  &proto,
	}

	if jwt != nil {
		tun.jwt = jwt
	}

	if serverAddr != nil {
		tun.ServerAddr = serverAddr
	} else {
		tun.ServerAddr = common.StringOrNil(fmt.Sprintf("%s:%d", pgrokDefaultServerHost, pgrokDefaultServerPort))
	}

	if shutdownFn != nil {
		tun.shutdownFn = shutdownFn
	}

	return tun, nil
}

// AddTunnel adds a new tunnel to the pgrok client
func (c *Client) AddTunnel(t *Tunnel) {
	c.Tunnels = append(c.Tunnels, t)
}

// Close disconnects all tunnels
func (c *Client) Close() {
	for _, t := range c.Tunnels {
		t.shutdown()
	}
}

// Closed returns true if all client tunnels have been disconnected
func (c *Client) Closed() bool {
	for _, t := range c.Tunnels {
		if !t.shuttingDown() {
			return false
		}
	}

	return true
}

// ConnectAll connects all tunnels
func (c *Client) ConnectAll() error {
	for _, t := range c.Tunnels {
		go t.main()
	}

	// TODO-- assert tunnel connectivity
	return nil
}
