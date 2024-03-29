package blacklistEntities

import (
	"errors"
	"fmt"
	"github.com/jackc/pgtype"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// STIX2Bundle represents IoC report in STIX 2.0 format
// reference: https://oasis-open.github.io/cti-documentation/stix/intro.html
type STIX2Bundle struct {
	Type string `json:"type"`
	ID   string `json:"id"`

	Objects []STIX2Object `json:"objects"`
}

type STIX2Object struct {
	Type          string     `json:"type"`
	SpecVersion   string     `json:"spec_version"`
	Id            string     `json:"id"`
	Created       time.Time  `json:"created"`
	CreatedByRef  string     `json:"created_by_ref,omitempty"`
	ValidFrom     time.Time  `json:"valid_from,omitempty"`
	Modified      time.Time  `json:"modified"`
	Published     *time.Time `json:"published,omitempty"`
	Revoked       *time.Time `json:"revoked,omitempty"`
	Name          string     `json:"name"`
	IdentityClass string     `json:"identity_class"`

	Description    string `json:"description,omitempty"`
	Pattern        string `json:"pattern,omitempty"`
	PatternType    string `json:"pattern_type,omitempty"`
	PatternVersion string `json:"pattern_version,omitempty"`

	KillChainPhases []struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	} `json:"kill_chain_phases"`

	Labels []string `json:"labels"`
}

var FilteredTypes = []string{
	"indicator",
}

var FilteredLabels = []string{
	"misp:type=\"ip-dst\"",
	"misp:type=\"url\"",
}

func (s *STIX2Object) ToBlackListedIP(sourceID uint64) (BlacklistedIP, error) {
	var ipAddress = pgtype.Inet{}

	if !strings.Contains(s.Pattern, "network-traffic:dst_ref.type = 'ipv4-addr'") {
		return BlacklistedIP{}, errors.New("IPv4 not found")
	} else {
		dstValue := ExtractIPFromPattern(s.Pattern)
		if len(dstValue) == 0 {
			return BlacklistedIP{}, errors.New("IPv4 not found")
		}

		err := ipAddress.Set(dstValue)
		if err != nil {
			return BlacklistedIP{}, err
		}
	}

	return BlacklistedIP{
		IPAddress:   ipAddress,
		Description: s.Description,
		SourceID:    sourceID,
	}, nil
}

func (s *STIX2Object) ToBlacklisted(extractAll bool) (*BlacklistedIP, *BlacklistedDomain, *BlacklistedURL, *BlacklistedEmail, error) {
	var ip_ *BlacklistedIP
	var domain_ *BlacklistedDomain
	var url_ *BlacklistedURL
	var email_ *BlacklistedEmail

	var sourceID uint64

	// set source
	if strings.HasPrefix(s.Description, "Vendor-DRWEB") {
		sourceID = SourceDrWeb
	} else if strings.HasPrefix(s.Description, "Vendor-Kaspersky") {
		sourceID = SourceKaspersky
	} else if strings.HasPrefix(s.Description, "FinCERT") {
		sourceID = SourceFinCERT
	} else {
		sourceID = SourceUnknown
		slog.Warn("indicator vendor not found")
	}

	if slices.Contains(s.Labels, "misp:type=\"ip-src\"") {
		value := ExtractIPFromPattern(s.Pattern)
		ip_ = &BlacklistedIP{
			IPAddress:    pgtype.Inet{},
			Description:  s.Description,
			SourceID:     sourceID,
			DiscoveredAt: s.ValidFrom,
		}

		err := ip_.IPAddress.Set(value)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		if !extractAll {
			return ip_, nil, nil, nil, nil
		}
	}

	// parsing URL destination
	// this could also be IP with path

	// find ip_ in pattern
	if extractAll {
		dstValue := ExtractIPFromPattern(s.Pattern)
		if len(dstValue) != 0 {
			ip_ = &BlacklistedIP{
				IPAddress:    pgtype.Inet{},
				Description:  s.Description,
				SourceID:     sourceID,
				DiscoveredAt: s.ValidFrom,
			}

			err := ip_.IPAddress.Set(dstValue)
			if err != nil {
				return nil, nil, nil, nil, err
			}
		}
	}

	if slices.Contains(s.Labels, "misp:type=\"url\"") {
		url_ = &BlacklistedURL{
			URL:          extractValueFromPattern(s.Pattern),
			Description:  s.Description,
			SourceID:     sourceID,
			DiscoveredAt: s.ValidFrom,
		}

		if !extractAll {
			return nil, nil, url_, nil, nil
		}

		// domain should be ejected only if IP not provided
		if ip_ == nil {
			if !strings.Contains(url_.URL, "http") {
				url_.URL = "//" + url_.URL
			}

			domain, err := url.Parse(url_.URL)
			if err == nil {
				if len(domain.Hostname()) == 0 {
					slog.Warn(fmt.Sprintf("hostname from URL '%s' in empty", url_.URL))
				}

				domain_ = &BlacklistedDomain{
					URN:          domain.Hostname(),
					Description:  s.Description,
					SourceID:     sourceID,
					DiscoveredAt: s.ValidFrom,
				}
			} else {
				slog.Warn(fmt.Sprintf("failed to parse hostname from URL '%s', error: %s", url_.URL, err.Error()))
			}
		}
	}

	if slices.Contains(s.Labels, "misp:type=\"email-src\"") {
		email_ = &BlacklistedEmail{
			Email:        extractValueFromPattern(s.Pattern),
			Description:  s.Description,
			SourceID:     sourceID,
			DiscoveredAt: s.ValidFrom,
		}

		if !extractAll {
			return nil, nil, nil, email_, nil
		}
	}

	return ip_, domain_, url_, email_, nil
}

// type, spec_version, id, created, modified
// need to eject types in [identity, indicator]

func extractValueFromPattern(input string) string {
	var re = regexp.MustCompile(`(?m)'(.+)'`)
	return strings.Trim(re.FindString(input), "'")
}
