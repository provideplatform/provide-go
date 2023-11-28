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
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/provideplatform/provide-go/common"
	"golang.org/x/crypto/ssh"
)

const pgrokClientDestinationReachabilityTimeout = 500 * time.Millisecond
const pgrokClientBufferSize = 512

// const pgrokClientDestinationReadDeadlineInterval = time.Millisecond * 1000
// const pgrokClientDestinationWriteDeadlineInterval = time.Millisecond * 1000
const pgrokClientChannelTypeForward = "forward"
const pgrokClientRequestTypeForwardAddr = "forward-addr"
const pgrokClientRequestTypeTunnelExpiration = "tunnel-expiration"
const pgrokClientRequestTypePing = "ping"
const pgrokClientStatusTickerInterval = 25 * time.Millisecond
const pgrokClientStatusSleepInterval = 50 * time.Millisecond
const pgrokConnSleepTimeout = time.Millisecond * 100
const pgrokConnSessionBufferSleepTimeout = time.Millisecond * 100
const pgrokDefaultServerHost = "0.pgrok.provide.technology"
const pgrokDefaultServerPort = 8022
const pgrokDefaultTunnelProtocol = "tcp"

type Tunnel struct {
	Name       *string
	Protocol   *string
	LocalAddr  *string
	RemoteAddr *string
	ServerAddr *string

	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context
	shutdownFn  func(reason *string)

	client    *ssh.Client
	channel   ssh.Channel
	jwt       *string
	mutex     *sync.Mutex
	requests  <-chan *ssh.Request
	session   *ssh.Session
	sessionID *string

	stderr io.Reader
	stdin  io.Writer
	stdout io.Reader
}

func (t *Tunnel) main() {
	common.Log.Debug("installing signal handlers for pgrok tunnel client")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	t.shutdownCtx, t.cancelF = context.WithCancel(context.Background())

	t.mutex = &sync.Mutex{}

	if t.ServerAddr == nil {
		t.ServerAddr = common.StringOrNil(fmt.Sprintf("%s:%d", pgrokDefaultServerHost, pgrokDefaultServerPort))
	}

	var err error
	t.client, err = ssh.Dial("tcp", *t.ServerAddr, sshClientConfigFactory())
	if err != nil {
		common.Log.Panicf("pgrok tunnel client failed to connect; %s", err.Error())
	}

	t.checkDestinationReachability()
	t.initSession()

	common.Log.Debugf("running pgrok tunnel client")
	timer := time.NewTicker(pgrokClientStatusTickerInterval)
	defer timer.Stop()

	for !t.shuttingDown() {
		select {
		case <-timer.C:
			t.tick()
		case sig := <-sigs:
			common.Log.Infof("received signal: %s", sig)
			t.shutdown()
		case <-t.shutdownCtx.Done():
			close(sigs)
		// TODO: handle tunnel EOF caused by freemium tunnel expiration
		default:
			time.Sleep(pgrokClientStatusSleepInterval)
		}
	}

	common.Log.Debug("exiting pgrok tunnel client")
}

func sshClientConfigFactory() *ssh.ClientConfig {
	cfg := &ssh.ClientConfig{
		// Config contains configuration that is shared between clients and
		// // servers.
		// Config

		// User contains the username to authenticate as.
		// User string

		// Auth contains possible authentication methods to use with the
		// server. Only the first instance of a particular RFC 4252 method will
		// be used during authentication.
		Auth: []ssh.AuthMethod{},

		// HostKeyCallback is called during the cryptographic
		// handshake to validate the server's host key. The client
		// configuration must supply this callback for the connection
		// to succeed. The functions InsecureIgnoreHostKey or
		// FixedHostKey can be used for simplistic host key checks.
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},

		// BannerCallback is called during the SSH dance to display a custom
		// server's message. The client configuration can supply this callback to
		// handle it as wished. The function BannerDisplayStderr can be used for
		// simplistic display on Stderr.
		// BannerCallback BannerCallback

		// ClientVersion contains the version identification string that will
		// be used for the connection. If empty, a reasonable default is used.
		ClientVersion: "SSH-2.0-pgrok-client",

		// HostKeyAlgorithms lists the key types that the client will
		// accept from the server as host key, in order of
		// preference. If empty, a reasonable default is used. Any
		// string returned from PublicKey.Type method may be used, or
		// any of the CertAlgoXxxx and KeyAlgoXxxx constants.
		// HostKeyAlgorithms []string

		// Timeout is the maximum amount of time for the TCP connection to establish.
		Timeout: time.Millisecond * 2500,
	}

	return cfg
}

func (t *Tunnel) shutdown() {
	if atomic.AddUint32(&t.closing, 1) == 1 {
		t.channel.Close()
		t.session.Close()
		t.client.Close()

		common.Log.Debug("shutting down pgrok tunnel client")
		t.cancelF()
	}
}

func (t *Tunnel) shuttingDown() bool {
	return (atomic.LoadUint32(&t.closing) > 0)
}

func (t *Tunnel) tick() {

}

func (t *Tunnel) initSession() {
	var err error
	t.session, err = t.client.NewSession()
	if err != nil {
		t.client.Close()
		common.Log.Panicf("pgrok tunnel client failed to open session; %s", err.Error())
	}

	t.sessionID = common.StringOrNil(hex.EncodeToString(t.client.SessionID()))
	common.Log.Debugf("pgrok tunnel session established: %s", *t.sessionID)

	t.stdin, err = t.session.StdinPipe()
	if err != nil {
		common.Log.Panicf("failed to resolve pgrok tunnel session stdin pipe; %s", err.Error())
	}

	t.stdout, err = t.session.StdoutPipe()
	if err != nil {
		common.Log.Panicf("failed to resolve pgrok tunnel session stdout pipe; %s", err.Error())
	}

	t.stderr, err = t.session.StderrPipe()
	if err != nil {
		common.Log.Panicf("failed to resolve pgrok tunnel session stderr pipe; %s", err.Error())
	}

	// stdout
	go func() {
		for !t.shuttingDown() {
			var n int
			buffer := make([]byte, pgrokClientBufferSize)
			if n, err = t.stdout.Read(buffer); err != nil && err != io.EOF {
				common.Log.Warningf("pgrok tunnel client failed to consume stdout stream; %s", err.Error())
			} else if n > 0 {
				common.Log.Tracef("pgrok tunnel client read %d bytes from ssh stdout stream", n)
			}
			time.Sleep(pgrokConnSessionBufferSleepTimeout)
		}
	}()

	// stderr
	go func() {
		for !t.shuttingDown() {
			var n int
			buffer := make([]byte, pgrokClientBufferSize)
			if n, err = t.stderr.Read(buffer); err != nil && err != io.EOF {
				common.Log.Warningf("pgrok tunnel client failed to consume stderr stream; %s", err.Error())
			} else if n > 0 {
				common.Log.Tracef("pgrok tunnel client read %d bytes from ssh stderr stream", n)
			}
			time.Sleep(pgrokConnSessionBufferSleepTimeout)
		}
	}()

	err = t.initChannel()
	if err != nil {
		common.Log.Panicf("failed to initialize channel; %s", err.Error())
	}

	go func() {
		c := t.client.HandleChannelOpen(pgrokClientChannelTypeForward)
		for !t.shuttingDown() {
			if newChannel := <-c; newChannel != nil {
				fchan, freqs, err := newChannel.Accept()
				if err != nil {
					common.Log.Warningf("pgrok tunnel client failed to accept %s channel for %s; %s", pgrokClientChannelTypeForward, *t.LocalAddr, err.Error())
				} else {
					go func() {
						for req := range freqs {
							req.Reply(true, nil)
						}
					}()

					go t.forward(fchan)
				}
			}

			time.Sleep(pgrokConnSessionBufferSleepTimeout)
		}
	}()
}

func (t *Tunnel) initChannel() error {
	payload := make([]byte, 0)
	if t.jwt != nil {
		payload = []byte(*t.jwt)
	}

	var err error
	t.channel, t.requests, err = t.client.OpenChannel(fmt.Sprintf("session:%s", *t.sessionID), payload)
	if err != nil {
		common.Log.Warningf("pgrok tunnel client failed to open channel; %s", err.Error())
		return err
	}

	// sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range t.requests {
			switch req.Type {
			case pgrokClientRequestTypeTunnelExpiration:
				req.Reply(true, nil)
				msg := "pgrok tunnel client expired;\n\n\tPurchase additional subscription capacity 🥳 🎉"
				common.Log.Info(msg)
				t.shutdown()
				if t.shutdownFn != nil {
					t.shutdownFn(&msg)
				}
			case pgrokClientRequestTypeForwardAddr:
				common.Log.Debugf("pgrok tunnel client received response to %s request: %s", pgrokClientRequestTypeForwardAddr, string(req.Payload))
				payload := map[string]interface{}{}
				err := json.Unmarshal(req.Payload, &payload)
				if err != nil {
					common.Log.Warningf("pgrok tunnel client failed to parse response to %s request; %s", pgrokClientRequestTypeForwardAddr, err.Error())
					req.Reply(false, nil)
				}
				if addr, addrOk := payload["addr"].(string); addrOk {
					t.RemoteAddr = &addr
					common.Log.Debugf("pgrok tunnel client resolved address: %s", *t.RemoteAddr)
				}
				req.Reply(true, nil)
			case pgrokClientRequestTypePing:
				common.Log.Debug("pgrok tunnel client received ping request")
				req.Reply(true, []byte("pong"))
			}
		}
	}()

	// send forwarding request
	proto := make([]byte, 0)
	if t.Protocol != nil {
		proto = []byte(*t.Protocol)
	}

	_, err = t.channel.SendRequest(pgrokClientRequestTypeForwardAddr, true, proto)
	if err != nil {
		return err
	}

	if t.RemoteAddr != nil && t.LocalAddr != nil {
		common.Log.Debugf("pgrok tunnel client opened channel; forwarding %s -> %s", *t.RemoteAddr, *t.LocalAddr)
	}

	return nil
}

func (t *Tunnel) forward(channel ssh.Channel) {
	dest, err := net.Dial("tcp", *t.LocalAddr)
	if err != nil {
		common.Log.Warningf("pgrok tunnel client failed to dial local destination address %s; %s", *t.LocalAddr, err.Error())
		// channel.Close()
		// return
	}

	var once sync.Once

	close := func() {
		if dest != nil {
			dest.Close()
			dest = nil
		}
	}

	redial := func() {
		if dest != nil {
			common.Log.Tracef("pgrok tunnel client closing pipe to local destination: %s", *t.LocalAddr)
			dest.Close()
			dest = nil
		}

		var err error
		dest, err = net.Dial("tcp", *t.LocalAddr)
		if err != nil {
			common.Log.Warningf("pgrok tunnel client failed to redial local destination address %s; %s", *t.LocalAddr, err.Error())
		} else {
			common.Log.Debugf("pgrok tunnel client redialed local destination: %s", *t.LocalAddr)
		}
	}

	// channel > local destination
	go func() {
		for !t.shuttingDown() {
			if dest != nil {
				var n int
				var err error
				buffer := make([]byte, pgrokClientBufferSize)
				if n, err = channel.Read(buffer); err != nil && err != io.EOF {
					common.Log.Warningf("pgrok tunnel client failed to read from channel; %s", err.Error())
				} else if n > 0 {
					common.Log.Tracef("pgrok tunnel client wrote %d bytes from channel to local destination (%s)", n, *t.LocalAddr)
					i, err := dest.Write(buffer[0:n])
					if err != nil {
						common.Log.Warningf("pgrok tunnel client failed to write %d bytes from local destination (%s) to channel; %s", n, *t.LocalAddr, err.Error())
						if errors.Is(err, syscall.EPIPE) {
							redial()
						}
					} else {
						common.Log.Tracef("pgrok tunnel client wrote %d bytes from local destination (%s) to channel", i, *t.LocalAddr)
					}
				}
			}

			time.Sleep(pgrokConnSessionBufferSleepTimeout)
		}

		once.Do(close)
	}()

	go func() {
		for !t.shuttingDown() {
			io.Copy(io.Discard, channel.Stderr())
			time.Sleep(pgrokConnSessionBufferSleepTimeout)
		}

		once.Do(close)
	}()

	// local destination > channel
	go func() {
		for !t.shuttingDown() {
			if dest != nil {
				var n int
				var err error
				buffer := make([]byte, pgrokClientBufferSize)
				if n, err = dest.Read(buffer); err != nil && err != io.EOF {
					common.Log.Warningf("pgrok tunnel client failed to read from local destination (%s); %s", *t.LocalAddr, err.Error())
					if errors.Is(err, syscall.EPIPE) {
						redial()
					}
				} else if n > 0 {
					i, err := channel.Write(buffer[0:n])
					if err != nil {
						common.Log.Warningf("pgrok tunnel client failed to write %d bytes from local destination (%s) to channel; %s", n, *t.LocalAddr, err.Error())
					} else {
						common.Log.Tracef("pgrok tunnel client wrote %d bytes from local destination (%s) to channel", i, *t.LocalAddr)
					}
				}
			}

			time.Sleep(pgrokConnSleepTimeout)
		}

		once.Do(close)
	}()
}

// checkDestinationReachability just logs a warning as of now if the destination address is not currently reachable;
// i.e., if localhost:4222 is not up when this is called, it will log a warning
func (t *Tunnel) checkDestinationReachability() {
	conn, err := net.DialTimeout("tcp", *t.LocalAddr, pgrokClientDestinationReachabilityTimeout)
	if err != nil {
		common.Log.Warningf("pgrok tunnel client destination address unreachable: %s; %s", *t.LocalAddr, err.Error())
		return
	}
	conn.Close()
}
