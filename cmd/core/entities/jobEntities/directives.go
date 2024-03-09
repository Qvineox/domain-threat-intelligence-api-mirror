package jobEntities

import (
	"domain_threat_intelligence_api/api/grpc/protoServices"
)

type Directives struct {
	OpenSourceScanDirectives *OSSDirectives       `json:"OpenSourceScanDirectives,omitempty"`
	NMAPDirectives           *NMAPDirectives      `json:"NMAPDirectives,omitempty"`
	WhoISDirectives          *WhoISDirectives     `json:"WhoISDirectives,omitempty"`
	DNSDirectives            *DNSDirectives       `json:"DNSDirectives,omitempty"`
	DiscoveryDirectives      *DiscoveryDirectives `json:"DiscoveryDirectives,omitempty"`
	SpiderDirectives         *SpiderDirectives    `json:"SpiderDirectives,omitempty"`
}

type OSSDirectives struct {
	Providers []SupportedOSSProvider `json:"Providers"`

	Timings *DirectiveTimings `json:"Timings"`
}

type NMAPDirectives struct {
	Timings *DirectiveTimings `json:"Timings"`
}

type WhoISDirectives struct {
	Timings *DirectiveTimings `json:"Timings"`
}

type DNSDirectives struct {
	Timings *DirectiveTimings `json:"Timings"`
}

type DiscoveryDirectives struct {
	Ports  []int64 `json:"Ports"`
	Silent bool    `json:"Silent"`

	Timings *DirectiveTimings `json:"Timings" json:"Timings"`
}

type SpiderDirectives struct {
	Depth uint64 `json:"Depth"`

	Timings *DirectiveTimings `json:"Timings"`
}

type DirectiveTimings struct {
	Timeout uint64 `json:"Timeout" binding:"required"`
	Delay   uint64 `json:"Delay" binding:"required"`
	Reties  uint64 `json:"Reties" binding:"required"`
}

func (t DirectiveTimings) ToProto() *protoServices.Timings {
	return &protoServices.Timings{
		Timeout: t.Timeout,
		Delay:   t.Delay,
		Retries: t.Reties,
	}
}

type SupportedOSSProvider uint64

const (
	OSS_PROVIDER_VIRUS_TOTAL SupportedOSSProvider = iota
	OSS_PROVIDER_IP_QUALITY_SCORE
	OSS_PROVIDER_CROWD_SEC
	OSS_PROVIDER_SHODAN
	OSS_PROVIDER_IP_WHO_IS
)

func (d *Directives) ToProto() *protoServices.Directives {
	pd := protoServices.Directives{}

	if d.OpenSourceScanDirectives != nil {
		var providers = make([]protoServices.OSSProvider, 0)

		for _, p := range d.OpenSourceScanDirectives.Providers {
			providers = append(providers, protoServices.OSSProvider(p))
		}

		pd.Oss = &protoServices.OSSDirectives{
			Providers: providers,
		}

		pd.Oss.Timings = d.OpenSourceScanDirectives.Timings.ToProto()
	}

	// TODO: add other Directives

	return &pd
}
