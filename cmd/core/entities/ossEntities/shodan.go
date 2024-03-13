package ossEntities

// ShodanHostScanBody https://datapedia.shodan.io/
type ShodanHostScanBody struct {
	// host info
	Tags     []string `json:"tags"`
	AreaCode string   `json:"area_code"`
	Org      string   `json:"org"`
	Asn      string   `json:"asn"`
	Isp      string   `json:"isp"`

	// host info -> geography
	RegionCode  string  `json:"region_code"`
	CountryName string  `json:"country_name"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`

	// host info -> network
	Ip    int    `json:"ip"`
	IpStr string `json:"ip_str"`

	// domain info
	Domains   []string `json:"domains"`
	Hostnames []string `json:"hostnames"`

	// banners
	Os    string        `json:"os"`
	Ports []int         `json:"ports"`
	Data  []interface{} `json:"data"` // composite polymorph data

	// timestamps
	LastUpdate string `json:"last_update"`
}

func (report ShodanHostScanBody) GetRiskScore() *uint8 {
	var score uint8 = 50
	return &score
}
