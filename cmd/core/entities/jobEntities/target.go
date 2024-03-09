package jobEntities

import (
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"errors"
	"net"
	"net/mail"
	"net/url"
	"strings"
)

type Target struct {
	Host string     `json:"Host"`
	Type TargetType `json:"Type"`
}

type TargetType uint64

const (
	HOST_TYPE_CIDR TargetType = iota
	HOST_TYPE_DOMAIN
	HOST_TYPE_URL
	HOST_TYPE_EMAIL
)

// accepted examples:
// http://example.com		Domain
// https://example.com		Domain
// //example.com			Domain
// //example.com:80			Domain
// example.com				Domain
// http://example.com/path	URL
// http://10.20.10.1/path	URL
// example@example.com		Email
// 10.20.10.1				IP
// 10.20.10.1/32			IP
// 10.20.10.0/24			CIDR Subnet

// NewTargetFromString matches targets and sets type from string
func NewTargetFromString(target string) (Target, error) {
	// if host contains schema definition
	if strings.Contains(target, "//") {
		parsedURL, err := url.Parse(target)
		if err != nil {
			return Target{}, err
		}

		return Target{
			Host: parsedURL.String(),
			Type: HOST_TYPE_URL,
		}, nil
	}

	if strings.Contains(target, "@") {
		email, err := mail.ParseAddress(target)
		if err != nil {
			return Target{}, err
		}

		return Target{
			Host: email.String(),
			Type: HOST_TYPE_EMAIL,
		}, err
	}

	if strings.Contains(target, "/") {
		_, ipv4Net, err := net.ParseCIDR(target)
		if err == nil && ipv4Net != nil {
			return Target{
				Host: ipv4Net.String(),
				Type: HOST_TYPE_CIDR,
			}, nil
		}

		return Target{}, errors.New("failed to parse CIDR: " + err.Error())
	}

	ipv4Addr := net.ParseIP(target)
	if ipv4Addr == nil {
		_, err := url.Parse("//" + target)
		if err != nil {
			return Target{}, errors.New("unrecognized host type")
		}

		return Target{
			Host: target,
			Type: HOST_TYPE_DOMAIN,
		}, nil
	}

	return Target{
		Host: ipv4Addr.String() + "/32",
		Type: HOST_TYPE_CIDR,
	}, nil
}

func (t *Target) ToProto() *protoServices.Target {
	var target = protoServices.Target{
		Host: t.Host,
	}

	switch t.Type {
	case HOST_TYPE_CIDR:
		target.Type = protoServices.HostType_HOST_TYPE_CIDR
	case HOST_TYPE_DOMAIN:
		target.Type = protoServices.HostType_HOST_TYPE_CIDR
	case HOST_TYPE_URL:
		target.Type = protoServices.HostType_HOST_TYPE_URL
	case HOST_TYPE_EMAIL:
		target.Type = protoServices.HostType_HOST_TYPE_EMAIL
	}

	return &target
}
