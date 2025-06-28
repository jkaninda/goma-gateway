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

package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

func NewProxyServer(rules []ForwardRule, ctxt context.Context) *ProxyServer {
	ctx, cancel := context.WithCancel(ctxt)
	return &ProxyServer{
		rules:    rules,
		ctx:      ctx,
		cancel:   cancel,
		shutdown: make(chan struct{}),
	}
}

func (ps *ProxyServer) Start() error {
	if ps == nil || len(ps.rules) == 0 {
		return nil
	}
	for _, rule := range ps.rules {
		if err := ps.validateRule(rule); err != nil {
			return fmt.Errorf("invalid rule for port %d: %w", rule.Port, err)
		}

		ps.wg.Add(1)
		switch rule.Protocol {
		case ProtocolTCP:
			go ps.startTCPListener(rule)
		case ProtocolUDP:
			go ps.startUDPListener(rule)
		}

	}

	logger.Info("Proxy server started", "rules", len(ps.rules))
	return nil
}

func (ps *ProxyServer) Stop() {
	if ps == nil || len(ps.rules) == 0 {
		return
	}
	logger.Info("Shutting down proxy server")
	ps.cancel()
	ps.wg.Wait()
	close(ps.shutdown)
	logger.Info("Proxy server stopped")
}

func (ps *ProxyServer) validateRule(rule ForwardRule) error {
	if rule.Port <= 0 || rule.Port > 65535 {
		return fmt.Errorf("invalid port: %d", rule.Port)
	}
	if rule.Target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	if rule.Protocol != ProtocolTCP && rule.Protocol != ProtocolUDP {
		return fmt.Errorf("unsupported protocol: %s", rule.Protocol)
	}
	return nil
}

func (ps *ProxyServer) startTCPListener(rule ForwardRule) {
	defer ps.wg.Done()

	addr := fmt.Sprintf(":%d", rule.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Fatal("Failed to start TCP listener",
			"port", rule.Port, "error", err)
		return
	}

	logger.Info("TCP Listening for connections",
		"port", rule.Port, "target", rule.Target)

	go ps.acceptTCPConnections(listener, rule)

	// Wait for shutdown signal
	<-ps.ctx.Done()

	if err := listener.Close(); err != nil {
		logger.Error("Failed to close TCP listener",
			"port", rule.Port, "error", err)
	}
}

func (ps *ProxyServer) startUDPListener(rule ForwardRule) {
	defer ps.wg.Done()

	addr := fmt.Sprintf(":%d", rule.Port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		logger.Fatal("Failed to start UDP listener",
			"port", rule.Port, "error", err)
		return
	}

	logger.Info("UDP Listening for packets",
		"port", rule.Port, "target", rule.Target)

	go ps.handleUDPPackets(conn, rule)

	// Wait for shutdown signal
	<-ps.ctx.Done()

	if err := conn.Close(); err != nil {
		logger.Error("Failed to close UDP listener",
			"port", rule.Port, "error", err)
	}
}

func (ps *ProxyServer) acceptTCPConnections(listener net.Listener, rule ForwardRule) {
	for {
		select {
		case <-ps.ctx.Done():
			return
		default:
		}

		// Set accept timeout to allow periodic context checks
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			err := tcpListener.SetDeadline(time.Now().Add(10 * time.Second))
			if err != nil {
				logger.Warn("Failed to set deadline")
				return
			}
		}

		clientConn, err := listener.Accept()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}

			select {
			case <-ps.ctx.Done():
				return
			default:
				logger.Error("Failed to accept TCP connection",
					"port", rule.Port, "error", err)
				continue
			}
		}

		go ps.handleTCPConnection(clientConn, rule)
	}
}

func (ps *ProxyServer) handleUDPPackets(conn net.PacketConn, rule ForwardRule) {
	// Map to track client sessions for UDP
	sessions := make(map[string]*udpSession)
	sessionsMutex := sync.RWMutex{}
	// Max UDP packet size
	buffer := make([]byte, 65536)

	for {
		select {
		case <-ps.ctx.Done():
			// Close all sessions
			sessionsMutex.Lock()
			for _, session := range sessions {
				session.close()
			}
			sessionsMutex.Unlock()
			return
		default:
		}

		// Set read timeout to allow periodic context checks
		err := conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if err != nil {
			logger.Warn("Failed to set read deadline")
			return
		}

		n, clientAddr, err := conn.ReadFrom(buffer)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}

			select {
			case <-ps.ctx.Done():
				return
			default:
				logger.Error("Failed to read UDP packet", "error", err)
				continue
			}
		}

		clientKey := clientAddr.String()

		sessionsMutex.RLock()
		session, exists := sessions[clientKey]
		sessionsMutex.RUnlock()

		if !exists {
			// Create new session
			session = ps.createUDPSession(conn, clientAddr, rule)
			if session != nil {
				sessionsMutex.Lock()
				sessions[clientKey] = session
				sessionsMutex.Unlock()

				// Start cleanup goroutine for this session
				go func(key string) {
					<-session.done
					sessionsMutex.Lock()
					delete(sessions, key)
					sessionsMutex.Unlock()
				}(clientKey)
			} else {
				continue
			}
		}

		// Forward packet to target
		if session != nil {
			session.forwardToTarget(buffer[:n])
		}
	}
}

func (ps *ProxyServer) createUDPSession(clientConn net.PacketConn, clientAddr net.Addr, rule ForwardRule) *udpSession {
	targetConn, err := ps.dialWithTimeout("udp", rule.Target, 10*time.Second)
	if err != nil {
		logger.Error("Failed to connect to UDP target",
			"target", rule.Target, "error", err)
		return nil
	}

	ctx, cancel := context.WithCancel(ps.ctx)
	session := &udpSession{
		clientConn:   clientConn,
		clientAddr:   clientAddr,
		targetConn:   targetConn,
		rule:         rule,
		lastActivity: time.Now(),
		done:         make(chan struct{}),
		ctx:          ctx,
		cancel:       cancel,
	}

	logger.Info("UDP session created",
		"client", clientAddr, "target", rule.Target)

	// Start goroutine to handle responses from target
	go session.handleTargetResponses()

	// Start session timeout handler
	go session.handleTimeout()

	return session
}

func (s *udpSession) forwardToTarget(data []byte) {
	s.lastActivity = time.Now()
	_, err := s.targetConn.Write(data)
	if err != nil {
		logger.Error("Failed to forward UDP packet to target",
			"target", s.rule.Target, "error", err)
	}
}

func (s *udpSession) handleTargetResponses() {
	defer s.close()

	buffer := make([]byte, 65536)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		err := s.targetConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		if err != nil {
			logger.Error("Failed to set read deadline")
			return
		}
		n, err := s.targetConn.Read(buffer)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if err != io.EOF {
				logger.Error("Failed to read from UDP target", "error", err)
			}
			return
		}

		s.lastActivity = time.Now()
		_, err = s.clientConn.WriteTo(buffer[:n], s.clientAddr)
		if err != nil {
			logger.Error("Failed to forward UDP response to client", "error", err)
			return
		}
	}
}

func (s *udpSession) handleTimeout() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if time.Since(s.lastActivity) > 5*time.Minute {
				logger.Info("UDP session timeout",
					"client", s.clientAddr, "target", s.rule.Target)
				s.close()
				return
			}
		}
	}
}

func (s *udpSession) close() {
	s.cancel()
	err := s.targetConn.Close()
	if err != nil {
		logger.Error("Failed to close UDP connection", "error", err)
		return
	}
	close(s.done)
}

func (ps *ProxyServer) handleTCPConnection(clientConn net.Conn, rule ForwardRule) {
	defer ps.closeConnection(clientConn, "client")

	logger.Info("Accepted TCP client connection",
		"client", clientConn.RemoteAddr(), "target", rule.Target)

	serverConn, err := ps.dialWithTimeout("tcp", rule.Target, 10*time.Second)
	if err != nil {
		logger.Error("Failed to connect to TCP target",
			"target", rule.Target, "error", err)
		return
	}
	defer ps.closeConnection(serverConn, "server")

	logger.Info("TCP Proxying started",
		"client", clientConn.RemoteAddr(), "target", rule.Target)

	ps.proxyData(clientConn, serverConn)

	logger.Info("TCP Connection closed",
		"client", clientConn.RemoteAddr(), "target", rule.Target)
}

func (ps *ProxyServer) dialWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ps.ctx, timeout)
	defer cancel()

	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (ps *ProxyServer) proxyData(clientConn, serverConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client → Server
	go func() {
		defer wg.Done()
		ps.copyData(serverConn, clientConn, "client->server")
		ps.closeWrite(serverConn)
	}()

	// Server → Client
	go func() {
		defer wg.Done()
		ps.copyData(clientConn, serverConn, "server->client")
		ps.closeWrite(clientConn)
	}()

	wg.Wait()
}

func (ps *ProxyServer) copyData(dst, src net.Conn, direction string) {
	_, err := io.Copy(dst, src)
	if err != nil && !ps.isConnectionClosed(err) {
		logger.Error("Error copying data",
			"direction", direction,
			"src", src.RemoteAddr(),
			"dst", dst.RemoteAddr(),
			"error", err)
	}
}

func (ps *ProxyServer) closeWrite(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.CloseWrite(); err != nil {
			logger.Warn("Failed to close write",
				"addr", conn.RemoteAddr(), "error", err)
		}
	}
}

func (ps *ProxyServer) closeConnection(conn net.Conn, connType string) {
	if err := conn.Close(); err != nil {
		logger.Warn("Failed to close connection",
			"type", connType, "addr", conn.RemoteAddr(), "error", err)
	}
}

func (ps *ProxyServer) isConnectionClosed(err error) bool {
	if err == io.EOF {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}
