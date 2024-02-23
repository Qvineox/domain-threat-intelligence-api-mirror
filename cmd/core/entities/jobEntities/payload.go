package jobEntities

import (
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"log/slog"
)

type Payload struct {
	Targets    []Target `json:"Targets"`
	Exceptions []Target `json:"Exceptions"`
}

// NewPayload accepts targets as follows: URL, domain, email, CIDR, IP
func NewPayload(targets, exceptions []string) *Payload {
	p := Payload{
		Targets:    make([]Target, 0),
		Exceptions: make([]Target, 0),
	}

	for _, host := range targets {
		t, err := NewTargetFromString(host)
		if err != nil {
			slog.Warn("failed to created job target: " + err.Error())
			continue
		}

		p.Targets = append(p.Targets, t)
	}

	for _, host := range exceptions {
		t, err := NewTargetFromString(host)
		if err != nil {
			slog.Warn("failed to created job target: " + err.Error())
			continue
		}

		p.Exceptions = append(p.Exceptions, t)
	}

	return &p
}

func (p *Payload) ToProto() *protoServices.Payload {
	pp := protoServices.Payload{}

	for _, t := range p.Targets {
		pp.Targets = append(pp.Targets, t.ToProto())
	}

	for _, e := range p.Exceptions {
		pp.Exceptions = append(pp.Exceptions, e.ToProto())
	}

	return &pp
}
