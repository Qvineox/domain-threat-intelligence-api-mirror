package ossEntities

import (
	"math"
	"time"
)

type IPQSMaliciousURLScanBody struct {
	// method response status
	RequestId string `json:"request_id"`
	Message   string `json:"message"`
	Success   bool   `json:"success"`

	// host info
	Unsafe    bool   `json:"unsafe"`
	IpAddress string `json:"ip_address"`
	Server    string `json:"server"`

	// content info
	CountryCode  string `json:"country_code"`
	LanguageCode string `json:"language_code"`
	ContentType  string `json:"content_type"`
	PageSize     int    `json:"page_size"`
	StatusCode   int    `json:"status_code"`
	Category     string `json:"category"`

	// domain info
	Parking    bool   `json:"parking"`
	DomainRank int    `json:"domain_rank"`
	DnsValid   bool   `json:"dns_valid"`
	Domain     string `json:"domain"`
	DomainAge  struct {
		Human     string    `json:"human"`
		Timestamp int       `json:"timestamp"`
		Iso       time.Time `json:"iso"`
	} `json:"domain_age"`

	// malware info
	Spamming   bool  `json:"spamming"`
	Malware    bool  `json:"malware"`
	Phishing   bool  `json:"phishing"`
	Suspicious bool  `json:"suspicious"`
	Adult      bool  `json:"adult"`
	RiskScore  uint8 `json:"risk_score"`

	// uncategorized
	Redirected bool `json:"redirected"`
}

type IPQSPrivacyScanBody struct {
	// method response status
	RequestId string `json:"request_id"`
	Message   string `json:"message"`
	Success   bool   `json:"success"`

	// host info
	ISP          string `json:"ISP"`
	Organization string `json:"organization"`
	ASN          int    `json:"ASN"`
	Host         string `json:"host"`

	// host info -> geography
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Region      string  `json:"region"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ZipCode     string  `json:"zip_code"`
	Timezone    string  `json:"timezone"`

	// host info -> machine info
	OperatingSystem string `json:"operating_system"`
	Browser         string `json:"browser"`
	DeviceModel     string `json:"device_model"`
	DeviceBrand     string `json:"device_brand"`
	Mobile          bool   `json:"mobile"`

	// privacy info
	Proxy bool `json:"proxy"`
	Vpn   bool `json:"vpn"`
	Tor   bool `json:"tor"`
	// ConnectionType string `json:"connection_type"`
	// ActiveVpn      bool   `json:"active_vpn"`
	// ActiveTor      bool   `json:"active_tor"`

	// malware info
	IsCrawler   bool  `json:"is_crawler"`
	FraudScore  uint8 `json:"fraud_score"`
	RecentAbuse bool  `json:"recent_abuse"`
	// AbuseVelocity string `json:"abuse_velocity"`
	// BotStatus bool `json:"bot_status"`

	TransactionDetails struct {
		RiskScore   int      `json:"risk_score"`
		RiskFactors []string `json:"risk_factors"`

		ValidBillingAddress       bool   `json:"valid_billing_address"`
		ValidShippingAddress      bool   `json:"valid_shipping_address"`
		ValidBillingEmail         bool   `json:"valid_billing_email"`
		ValidShippingEmail        bool   `json:"valid_shipping_email"`
		RiskyBillingPhone         bool   `json:"risky_billing_phone"`
		RiskyShippingPhone        bool   `json:"risky_shipping_phone"`
		BillingPhoneCarrier       string `json:"billing_phone_carrier"`
		ShippingPhoneCarrier      string `json:"shipping_phone_carrier	"`
		BillingPhoneLineType      string `json:"billing_phone_line_type"`
		ShippingPhoneLineType     string `json:"shipping_phone_line_type"`
		BillingPhoneCountry       string `json:"billing_phone_country"`
		BillingPhoneCountryCode   string `json:"billing_phone_country_code"`
		ShippingPhoneCountry      string `json:"shipping_phone_country"`
		ShippingPhoneCountryCode  string `json:"shipping_phone_country_code"`
		FraudulentBehavior        bool   `json:"fraudulent_behavior"`
		BinCountry                string `json:"bin_country"`
		BinType                   string `json:"bin_type"`
		BinBankName               string `json:"bin_bank_name"`
		IsPrepaidCard             bool   `json:"is_prepaid_card"`
		RiskyUsername             bool   `json:"risky_username"`
		ValidBillingPhone         bool   `json:"valid_billing_phone"`
		ValidShippingPhone        bool   `json:"valid_shipping_phone"`
		LeakedBillingEmail        bool   `json:"leaked_billing_email"`
		LeakedShippingEmail       bool   `json:"leaked_shipping_email"`
		LeakedUserData            bool   `json:"leaked_user_data"`
		UserActivity              string `json:"user_activity"`
		PhoneNameIdentityMatch    string `json:"phone_name_identity_match"`
		PhoneEmailIdentityMatch   string `json:"phone_email_identity_match"`
		PhoneAddressIdentityMatch string `json:"phone_address_identity_match"`
		EmailNameIdentityMatch    string `json:"email_name_identity_match"`
		NameAddressIdentityMatch  string `json:"name_address_identity_match"`
		AddressEmailIdentityMatch string `json:"address_email_identity_match"`
	} `json:"transaction_details"`
}

type IPQSEMailScanBody struct {
	// method response status
	Success   bool   `json:"success"`
	RequestId string `json:"request_id"`

	// email basic info
	Valid          bool   `json:"valid"`
	Disposable     bool   `json:"disposable"`
	Deliverability string `json:"deliverability"` // high, medium, low
	TimedOut       bool   `json:"timed_out"`

	// owner identity
	FirstName string `json:"first_name"`
	Generic   bool   `json:"generic"`
	Common    bool   `json:"common"`
	// UserActivity string `json:"user_activity"`

	// malicious scoring
	FraudScore     uint8  `json:"fraud_score"`
	Leaked         bool   `json:"leaked"`
	SmtpScore      uint8  `json:"smtp_score"`    // -1 to 3
	OverallScore   uint8  `json:"overall_score"` // 0 to 4
	Honeypot       bool   `json:"honeypot"`
	CatchAll       bool   `json:"catch_all"`
	Suspect        bool   `json:"suspect"`
	SpamTrapScore  string `json:"spam_trap_score"`
	SanitizedEmail string `json:"sanitized_email"`

	// domain info
	DnsValid           bool   `json:"dns_valid"`
	FrequentComplainer bool   `json:"frequent_complainer"`
	RecentAbuse        bool   `json:"recent_abuse"`
	SuggestedDomain    string `json:"suggested_domain"`
	// DomainVelocity     string `json:"domain_velocity"`

	// AssociatedNames struct {
	//	IsDisabled string   `json:"status"`
	//	Names  []string `json:"names"`
	// } `json:"associated_names"`

	// AssociatedPhoneNumbers struct {
	//	IsDisabled       string   `json:"status"`
	//	PhoneNumbers []string `json:"phone_numbers"`
	// } `json:"associated_phone_numbers"`

	FirstSeen struct {
		Human     string    `json:"human"`
		Timestamp int       `json:"timestamp"`
		Iso       time.Time `json:"iso"`
	} `json:"first_seen"`

	DomainAge struct {
		Human     string    `json:"human"`
		Timestamp int       `json:"timestamp"`
		Iso       time.Time `json:"iso"`
	} `json:"domain_age"`
}

func (report IPQSEMailScanBody) GetRiskScore() uint8 {
	return uint8(float32(report.FraudScore) / 100 * math.MaxUint8)
}

func (report IPQSMaliciousURLScanBody) GetRiskScore() uint8 {
	return uint8(float32(report.RiskScore) / 100 * math.MaxUint8)
}

func (report IPQSPrivacyScanBody) GetRiskScore() uint8 {
	return uint8(float32(report.FraudScore) / 100 * math.MaxUint8)
}
