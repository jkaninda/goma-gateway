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

package pkg

import (
	"fmt"
	"testing"
)

func TestValidateIPAddress(t *testing.T) {
	tests := []string{
		"192.168.1.100",
		"192.168.1.120",
	}
	for _, test := range tests {
		if validateIPAddress(test) {
			fmt.Println("Ip is valid")
		} else {
			fmt.Println("Ip is invalid")
		}
	}

}
func TestValidateIPOrCIDR(t *testing.T) {
	tests := []string{
		"192.168.1.100",
		"192.168.1.100",
		"192.168.1.100/32",
		"invalid-input",
		"192.168.1.100/33",
	}
	for _, test := range tests {
		isIP, isCIDR := isIPOrCIDR(test)
		if isIP {
			fmt.Printf("%s is an IP address\n", test)
		} else if isCIDR {
			fmt.Printf("%s is a CIDR\n", test)
		} else {
			fmt.Printf("%s is neither an IP address nor a CIDR\n", test)
		}
	}

}
