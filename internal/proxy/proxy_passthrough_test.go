/*
 * Copyright 2024 Jonas Kaninda
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
 *
 */

package proxy

import (
	"context"
	"fmt"
	"github.com/jkaninda/logger"
	"net"
	"testing"
	"time"
)

func TestPassThroughServer_StartTCPListener(t *testing.T) {
	addr := startTCPServer(t)

	waitForMockServer()
	rules := []ForwardRule{
		{
			Protocol: ProtocolTCP,
			Port:     8282,
			Target:   addr.String(),
		},
	}
	ptServer := NewProxyServer(rules, context.Background(), logger.New())
	err := ptServer.Start()
	if err != nil {
		t.Fatalf("Failed to start PassThroughServer: %v", err)
	}
	defer ptServer.Stop()

	waitForMockServer()
	// Test TCP forwarding
	conn, err := net.Dial("tcp", "localhost:8282")
	if err != nil {
		t.Fatalf("Failed to connect to PassThroughServer: %v", err)
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			t.Errorf("Failed to close connection: %v", err)
		}
	}(conn)
	message := "Hello, PassThroughServer!"
	_, err = conn.Write([]byte(message))
	if err != nil {
		t.Fatalf("Failed to write to PassThroughServer: %v", err)
	}
	buf := make([]byte, len(message))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read from PassThroughServer: %v", err)
	}
	received := string(buf[:n])
	if received != message {
		t.Fatalf("Expected '%s', got '%s'", message, received)
	}
}
func TestPassThroughServer_StartUDPListener(t *testing.T) {
	addr := startUDPServer(t)

	rules := []ForwardRule{
		{
			Protocol: ProtocolUDP,
			Port:     8383,
			Target:   addr.String(),
		},
	}

	ptServer := NewProxyServer(rules, context.Background(), logger.New())
	err := ptServer.Start()
	if err != nil {
		t.Fatalf("Failed to start PassThroughServer: %v", err)
	}
	defer ptServer.Stop()
	waitForMockServer()

	// Test UDP forwarding
	conn, err := net.Dial("udp", "localhost:8383")
	if err != nil {
		t.Fatalf("Failed to connect to PassThroughServer: %v", err)
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			t.Errorf("Failed to close connection: %v", err)
		}
	}(conn)
	message := "Hello, UDP PassThroughServer!"
	_, err = conn.Write([]byte(message))
	if err != nil {
		t.Fatalf("Failed to write to PassThroughServer: %v", err)
	}
	buf := make([]byte, len(message))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read from PassThroughServer: %v", err)
	}
	received := string(buf[:n])
	if received != message {
		t.Fatalf("Expected '%s', got '%s'", message, received)
	}

}

func startTCPServer(t *testing.T) net.Addr {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start TCP server: %v", err)
	}
	go func() {
		defer func(ln net.Listener) {
			err := ln.Close()
			if err != nil {
				t.Errorf("Failed to close TCP listener: %v", err)
			}
		}(ln)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer func(c net.Conn) {
					err := c.Close()
					if err != nil {
						t.Errorf("Failed to close TCP connection: %v", err)
					}
				}(c)
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					_, _ = c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	fmt.Printf("TCP server listening on %s (%s)\n", ln.Addr().Network(), ln.Addr().String())
	return ln.Addr()
}
func startUDPServer(t *testing.T) net.Addr {
	t.Helper()

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("Failed to start UDP server: %v", err)
	}
	go func() {
		defer func(conn *net.UDPConn) {
			err := conn.Close()
			if err != nil {
				t.Errorf("Failed to close UDP connection: %v", err)
			}
		}(conn)
		buf := make([]byte, 1024)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], clientAddr)
		}
	}()
	waitForMockServer()
	fmt.Printf("UDP server listening on %s (%s)\n", conn.LocalAddr().Network(), conn.LocalAddr().String())
	return conn.LocalAddr()
}
func waitForMockServer() {
	time.Sleep(1 * time.Second)
}
