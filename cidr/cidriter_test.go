package cidr_test

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/fmotalleb/mithra/cidr"
)

var testCIDRs = []string{ // Cloudflare ip ranges
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

func cidrRange(cidr string) (start, end uint32) {
	ip, ipnet, _ := net.ParseCIDR(cidr)
	mask := binary.BigEndian.Uint32(ipnet.Mask)
	base := binary.BigEndian.Uint32(ip.To4())
	start = base & mask
	end = start | ^mask
	return
}

func TestIteratorNext(t *testing.T) {
	for _, cidrStr := range testCIDRs {
		it, err := cidr.NewIPv4CIDR(cidrStr)
		if err != nil {
			t.Fatalf("parse %s: %v", cidrStr, err)
		}

		start, end := cidrRange(cidrStr)

		var first, last uint32
		count := 0

		for {
			ip, ok := it.Next()
			if !ok {
				break
			}
			v := binary.BigEndian.Uint32(ip)
			if count == 0 {
				first = v
			}
			last = v
			count++
		}

		if first != start {
			t.Fatalf("%s first ip mismatch: got %v want %v", cidrStr, first, start)
		}
		if last != end {
			t.Fatalf("%s last ip mismatch: got %v want %v", cidrStr, last, end)
		}

		expected := int(end-start) + 1
		if count != expected {
			t.Fatalf("%s count mismatch: got %d want %d", cidrStr, count, expected)
		}
	}
}

func TestIteratorSeq(t *testing.T) {
	for _, cidrStr := range testCIDRs {
		it, err := cidr.NewIPv4CIDR(cidrStr)
		if err != nil {
			t.Fatalf("parse %s: %v", cidrStr, err)
		}

		start, end := cidrRange(cidrStr)

		var first, last uint32
		count := 0

		for ip := range it.Seq() {
			v := binary.BigEndian.Uint32(ip)
			if count == 0 {
				first = v
			}
			last = v
			count++
		}

		if first != start {
			t.Fatalf("%s first ip mismatch (seq): got %v want %v", cidrStr, first, start)
		}
		if last != end {
			t.Fatalf("%s last ip mismatch (seq): got %v want %v", cidrStr, last, end)
		}

		expected := int(end-start) + 1
		if count != expected {
			t.Fatalf("%s count mismatch (seq): got %d want %d", cidrStr, count, expected)
		}
	}
}

func BenchmarkNext(b *testing.B) {
	for _, cidrStr := range testCIDRs {
		b.Run(cidrStr, func(b *testing.B) {
			it, _ := cidr.NewIPv4CIDR(cidrStr)
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				it.Reset()
				for {
					_, ok := it.Next()
					if !ok {
						break
					}
				}
			}
		})
	}
}

func BenchmarkSeq(b *testing.B) {
	for _, cidrStr := range testCIDRs {
		b.Run(cidrStr, func(b *testing.B) {
			it, _ := cidr.NewIPv4CIDR(cidrStr)
			seq := it.Seq()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				for el := range seq {
					_ = el
				}
			}
		})
	}
}
