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
	"github.com/jkaninda/logger"
	"net"
	"sync"
	"time"
)

type PassThroughServer struct {
	rules    []ForwardRule
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	logger   *logger.Logger
	shutdown chan struct{}
}
type udpSession struct {
	clientConn   net.PacketConn
	clientAddr   net.Addr
	targetConn   net.Conn
	rule         ForwardRule
	lastActivity time.Time
	done         chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	logger       *logger.Logger
}
type Protocol string
type ForwardRule struct {
	Protocol Protocol `yaml:"protocol,omitempty"`
	Port     int      `yaml:"port,omitempty"`
	Target   string   `yaml:"target,omitempty"`
}
