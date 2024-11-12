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
