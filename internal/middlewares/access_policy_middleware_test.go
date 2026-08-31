package middlewares

import "testing"

func TestIPInRangeAcrossOctets(t *testing.T) {
	cases := []struct {
		ip, start, end string
		want           bool
	}{
		{"10.0.1.30", "10.0.0.50", "10.0.3.20", true}, // regression: was false
		{"10.0.0.49", "10.0.0.50", "10.0.3.20", false},
		{"10.0.3.21", "10.0.0.50", "10.0.3.20", false},
		{"10.0.0.50", "10.0.0.50", "10.0.3.20", true},
		{"10.0.3.20", "10.0.0.50", "10.0.3.20", true},
		{"192.168.1.50", "192.168.1.25", "192.168.1.100", true},
		{"2001:db8::5", "2001:db8::1", "2001:db8::ff", true}, // regression: IPv6 never matched
		{"2001:db8::100", "2001:db8::1", "2001:db8::ff", false},
		{"10.0.1.30", "2001:db8::1", "2001:db8::ff", false}, // mixed families
	}
	for _, c := range cases {
		if got := ipInRange(c.ip, c.start, c.end); got != c.want {
			t.Errorf("ipInRange(%s, %s, %s) = %v, want %v", c.ip, c.start, c.end, got, c.want)
		}
	}
}
