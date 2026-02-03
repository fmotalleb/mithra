package config

import (
	"iter"
	"net"

	"github.com/fmotalleb/mithra/cidr"
)

type Config struct {
	CIDRs      []string `mapstructure:"cidr"`
	SNI        string   `mapstructure:"sni" default:"{{ .args.sni }}"`
	Timeout    int      `mapstructure:"timeout" default:"{{ .args.timeout }}"`
	Port       int      `mapstructure:"port" default:"{{ .args.port }}"`
	StatusCode int      `mapstructure:"status_code" default:"{{ .args.status_code }}"`

	SamplesMinimum int     `mapstructure:"sample_min" default:"{{ .args.sample_min }}"`
	SamplesMaximum int     `mapstructure:"sample_max" default:"{{ .args.sample_max }}"`
	SamplesChance  float64 `mapstructure:"sample_chance" default:"{{ .args.sample_chance }}"`
}

func (c *Config) ReadCIDRs() ([]*cidr.Iterator, error) {
	result := make([]*cidr.Iterator, len(c.CIDRs))
	var err error
	for i, cidrStr := range c.CIDRs {
		result[i], err = cidr.NewIPv4CIDR(cidrStr)
		if err != nil {
			return result, err
		}
	}
	return result, err
}

func (c *Config) ReadCIDRsSamples() ([]iter.Seq[net.IP], error) {
	cidrs, err := c.ReadCIDRs()
	if err != nil {
		return nil, err
	}
	samples := make([]iter.Seq[net.IP], len(cidrs))
	for i, iter := range cidrs {
		samples[i] = iter.SeqSampled(c.SamplesChance, c.SamplesMaximum, c.SamplesMinimum)
	}
	return samples, nil
}
