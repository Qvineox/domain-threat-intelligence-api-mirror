package ossEntities

import (
	"math"
)

type CrowdSecIPScanBody struct {
	Ip         string `json:"ip"`
	Reputation string `json:"reputation"`

	IpRange             string `json:"ip_range"`
	IpRangeScore        int    `json:"ip_range_score"`
	IpRange24           string `json:"ip_range_24"`
	IpRange24Reputation string `json:"ip_range_24_reputation"`
	IpRange24Score      int    `json:"ip_range_24_score"`

	AsName string `json:"as_name"`
	AsNum  int    `json:"as_num"`

	BackgroundNoiseScore int    `json:"background_noise_score"`
	BackgroundNoise      string `json:"background_noise"`
	Confidence           string `json:"confidence"`

	Location struct {
		Country   string  `json:"country"`
		City      string  `json:"city"`
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
	} `json:"location"`

	ReverseDns string `json:"reverse_dns"`

	Behaviors []struct {
		Name        string `json:"name"`
		Label       string `json:"label"`
		Description string `json:"description"`
	} `json:"behaviors"`

	References []struct {
		Name        string `json:"name"`
		Label       string `json:"label"`
		Description string `json:"description"`
	} `json:"references"`

	History struct {
		FirstSeen string `json:"first_seen"`
		LastSeen  string `json:"last_seen"`
		FullAge   int    `json:"full_age"`
		DaysAge   int    `json:"days_age"`
	} `json:"history"`

	Classifications struct {
		FalsePositives []struct {
			Name        string `json:"name"`
			Label       string `json:"label"`
			Description string `json:"description"`
		} `json:"false_positives"`

		Classifications []struct {
			Name        string `json:"name"`
			Label       string `json:"label"`
			Description string `json:"description"`
		} `json:"classifications"`
	} `json:"classifications"`

	MitreTechniques []struct {
		Name        string `json:"name"`
		Label       string `json:"label"`
		Description string `json:"description"`
	} `json:"mitre_techniques"`

	CVEs []string `json:"cves"`

	AttackDetails []struct {
		Name        string   `json:"name"`
		Label       string   `json:"label"`
		Description string   `json:"description"`
		References  []string `json:"references"`
	} `json:"attack_details"`

	TargetCountries struct {
	} `json:"target_countries"`

	Scores struct {
		Overall struct {
			Aggressiveness uint8 `json:"aggressiveness"`
			Threat         uint8 `json:"threat"`
			Trust          uint8 `json:"trust"`
			Anomaly        uint8 `json:"anomaly"`
			Total          uint8 `json:"total"`
		} `json:"overall"`

		LastDay struct {
			Aggressiveness uint8 `json:"aggressiveness"`
			Threat         uint8 `json:"threat"`
			Trust          uint8 `json:"trust"`
			Anomaly        uint8 `json:"anomaly"`
			Total          uint8 `json:"total"`
		} `json:"last_day"`

		LastWeek struct {
			Aggressiveness uint8 `json:"aggressiveness"`
			Threat         uint8 `json:"threat"`
			Trust          uint8 `json:"trust"`
			Anomaly        uint8 `json:"anomaly"`
			Total          uint8 `json:"total"`
		} `json:"last_week"`

		LastMonth struct {
			Aggressiveness uint8 `json:"aggressiveness"`
			Threat         uint8 `json:"threat"`
			Trust          uint8 `json:"trust"`
			Anomaly        uint8 `json:"anomaly"`
			Total          uint8 `json:"total"`
		} `json:"last_month"`
	} `json:"scores"`
}

func (report CrowdSecIPScanBody) GetRiskScore() uint8 {
	return uint8(float32(report.Scores.Overall.Total) / 5 * math.MaxUint8)
}
