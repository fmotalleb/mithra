package cidr

import (
	"encoding/binary"
	"errors"
	"iter"
	"math/rand/v2"
	"net"
)

type Iterator struct {
	cur   uint32
	last  uint32
	mask  uint32
	ipbuf net.IP
}

// NewIPv4 creates a zero-allocation iterator for an IPv4 CIDR.
func NewIPv4CIDR(cidr string) (*Iterator, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("not an IPv4 CIDR")
	}

	mask := binary.BigEndian.Uint32(ipnet.Mask)
	start := binary.BigEndian.Uint32(ip4) & mask
	end := start | ^mask

	it := &Iterator{
		cur:   start,
		last:  end,
		mask:  mask,
		ipbuf: make(net.IP, net.IPv4len),
	}

	return it, nil
}

// Next returns the next IP. The returned net.IP is reused.
func (it *Iterator) Next() (net.IP, bool) {
	if it.cur > it.last {
		return nil, false
	}

	binary.BigEndian.PutUint32(it.ipbuf, it.cur)
	it.cur++

	return it.ipbuf, true
}

// Reset resets the iterator to the first IP.
func (it *Iterator) Reset() {
	it.cur = it.first()
}

// Seq returns an iter.Seq for range-based iteration.
func (it *Iterator) Seq() iter.Seq[net.IP] {
	return func(yield func(net.IP) bool) {
		it.Reset()
		for {
			ip, ok := it.Next()
			if !ok {
				return
			}
			if !yield(ip) {
				return
			}
		}
	}
}

func (it *Iterator) first() uint32 {
	// last & mask = start of CIDR.
	// This is a fixed O(1) operation (~0.3ns).
	return it.last & it.mask
}

// SeqSampled returns an iter.Seq that yields at least minCount IPs,
// then applies probabilistic sampling with probability [0.0, 1.0],
// and stops after 'limit' items have been yielded.
func (it *Iterator) SeqSampled(probability float64, limit int, minCount int) iter.Seq[net.IP] {
	return func(yield func(net.IP) bool) {
		it.Reset()
		count := 0

		// clamp minCount if limit is smaller
		if limit > 0 && minCount > limit {
			minCount = limit
		}

		for {
			// stop if limit reached
			if limit > 0 && count >= limit {
				return
			}

			ip, ok := it.Next()
			if !ok {
				return
			}

			// always yield until minCount is reached
			if count < minCount {
				if !yield(ip) {
					return
				}
				count++
				continue
			}

			// probabilistic filter after minCount
			if rand.Float64() >= probability {
				continue
			}

			if !yield(ip) {
				return
			}

			count++
		}
	}
}
