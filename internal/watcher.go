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
	"github.com/fsnotify/fsnotify"
	"github.com/jkaninda/goma-gateway/internal/logger"
)

// watchExtraConfig watches the extra configuration directory for changes
func (gatewayServer GatewayServer) watchExtraConfig(r Router) {
	// Create a new watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Error("Failed to create watcher: %v", err)
		return
	}
	defer func(watcher *fsnotify.Watcher) {
		err = watcher.Close()
		if err != nil {
			logger.Fatal("Failed to close watcher: %v", err)
		}
	}(watcher)
	// Specify the directory to watch
	directory := gatewayServer.gateway.ExtraConfig.Directory
	// Add the directory to the watcher
	err = watcher.Add(directory)
	if err != nil {
		logger.Error("Failed to watch directory: %v", err)
		err = watcher.Close()
		if err != nil {
			logger.Error("Failed to close watcher: %v", err)
		}
		return
	}
	// Create a channel to receive events
	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Check if the event is a writing event
				if event.Op&fsnotify.Write == fsnotify.Write {
					// Update configuration
					logger.Info("Configuration changes detected, backend reload required")
					err = gatewayServer.Initialize()
					if err != nil {
						logger.Error("Failed to reload configuration: %v", err)
					} else {
						// Update the routes
						r.UpdateHandler(gatewayServer.gateway)
					}

				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.Error("Error: %v", err)
			}
		}
	}()
	// Wait for the done channel to receive a value
	<-done

}
