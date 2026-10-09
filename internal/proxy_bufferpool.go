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
	"net/http/httputil"
	"sync"
)

// proxyBufferPool backs httputil.ReverseProxy's response copying.
type proxyBufferPool struct {
	pool sync.Pool
}

// proxyBufferSize matches ReverseProxy's own default, so behaviour is unchanged
// for large responses; only the allocation is avoided.
const proxyBufferSize = 32 * 1024

func newProxyBufferPool() *proxyBufferPool {
	return &proxyBufferPool{
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, proxyBufferSize)
				return &b
			},
		},
	}
}

func (p *proxyBufferPool) Get() []byte {
	return *p.pool.Get().(*[]byte)
}

func (p *proxyBufferPool) Put(b []byte) {
	if cap(b) < proxyBufferSize {
		// Not one of ours; dropping it keeps the pool's buffers uniform.
		return
	}
	b = b[:proxyBufferSize]
	p.pool.Put(&b)
}

// Compile-time check that this satisfies what ReverseProxy expects.
var _ httputil.BufferPool = (*proxyBufferPool)(nil)
