package jobEntities

type Payload struct {
	Targets    []Target `json:"targets"`
	Exceptions []Target `json:"exceptions"`
}

// NewPayload accepts targets as follows: URL, domain, email, CIDR, IP
func NewPayload(targets, exceptions []string) (*Payload, error) {
	p := Payload{
		Targets:    make([]Target, 0),
		Exceptions: make([]Target, 0),
	}

	for _, host := range targets {
		t, err := NewTargetFromString(host)
		if err != nil {
			return nil, err
		}

		p.Targets = append(p.Targets, t)
	}

	for _, host := range exceptions {
		t, err := NewTargetFromString(host)
		if err != nil {
			return nil, err
		}

		p.Exceptions = append(p.Exceptions, t)
	}

	return &p, nil
}
