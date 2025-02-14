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

package util

import (
	"log"
	"testing"
	"time"
)

func TestConExpression(t *testing.T) {
	cronExpression := "@every 30s"
	if !IsValidCronExpression(cronExpression) {
		t.Fatal("Cron expression should be valid")
	}
	log.Println(" Cron is valid")

}

func TestParseDuration(t *testing.T) {
	d1, err1 := ParseDuration("20s")
	if err1 != nil {
		t.Error("Error:", err1)
	} else {
		log.Printf("Parsed duration: %d", d1)
		log.Printf("Time out: %s\n", time.Now().Add(d1))

	}
	d2, err2 := ParseDuration("10m")
	if err2 != nil {
		t.Errorf("Error: %v", err2)
	} else {
		log.Printf("Parsed duration: %d\n", d2)
		log.Printf("Time out: %s\n", time.Now().Add(d2))

	}
}
