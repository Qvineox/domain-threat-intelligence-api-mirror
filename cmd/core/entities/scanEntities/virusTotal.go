package scanEntities

// VTIPScanBody https://developers.virustotal.com/reference/ip-object
type VTIPScanBody struct {
	Data struct {
		Id   string `json:"id"`
		Type string `json:"type"`

		Attributes struct {
			// host info
			ASOwner   string   `json:"as_owner"`
			ASN       int      `json:"asn"`
			JARM      string   `json:"jarm"`
			Whois     string   `json:"whois"`
			WhoisDate int      `json:"whois_date"`
			Tags      []string `json:"tags"`

			// host info -> geography
			Continent string `json:"continent"`
			Country   string `json:"country"`

			// host info -> network
			Network                  string `json:"network"`
			RegionalInternetRegistry string `json:"regional_internet_registry"`

			// block list info
			LastAnalysisDate    int `json:"last_analysis_date"`
			LastAnalysisResults map[string]struct {
				Category   string `json:"category"`
				Result     string `json:"result"`
				Method     string `json:"method"`
				EngineName string `json:"engine_name"`
			} `json:"last_analysis_results"`

			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Timeout    int `json:"timeout"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`

			// encryption info
			LastHTTPSCertificate     VTSSLCertificate `json:"last_https_certificate"`
			LastHTTPSCertificateDate int              `json:"last_https_certificate_date"`

			// malware info
			Reputation int `json:"reputation"`
			TotalVotes struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`

			LastModificationDate int `json:"last_modification_date"`
		} `json:"attributes"`

		Links struct {
			Self string `json:"self"`
		} `json:"links"`
	} `json:"data"`
}

// VTSSLCertificate https://developers.virustotal.com/reference/ssl-certificate
type VTSSLCertificate struct {
	SerialNumber       string `json:"serial_number"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	Size               int    `json:"size"`

	Subject struct {
		C  string `json:"C"`
		CN string `json:"CN"`
		L  string `json:"L"`
		O  string `json:"O"`
		OU string `json:"OU"`
		ST string `json:"ST"`
	} `json:"subject"`

	CertSignature struct {
		Signature          string `json:"signature"`
		SignatureAlgorithm string `json:"signature_algorithm"`
	} `json:"cert_signature"`

	Extensions struct {
		CA bool `json:"CA"`

		AuthorityKeyIdentifier struct {
			Keyid        string `json:"keyid"`
			SerialNumber string `json:"serial_number"`
		} `json:"authority_key_identifier"`

		CAInformationAccess map[string]string `json:"ca_information_access"`

		CertificatePolicies        []string `json:"certificate_policies"`
		CertTemplateNameDc         string   `json:"cert_template_name_dc"`
		CrlDistributionPoints      []string `json:"crl_distribution_points"`
		ExtendedKeyUsage           []string `json:"extended_key_usage"`
		KeyUsage                   []string `json:"key_usage"`
		NetscapeCertComment        string   `json:"netscape_cert_comment"`
		NetscapeCertificate        bool     `json:"netscape_certificate"`
		OldAuthorityKeyIdentifier  bool     `json:"old_authority_key_identifier"`
		PeLogotype                 bool     `json:"pe_logotype"`
		SubjectAlternativeName     []string `json:"subject_alternative_name"`
		SubjectKeyIdentifier       string   `json:"subject_key_identifier"`
		AdditionalExtensionsString string   `json:"<additional extensions:string>"`

		Tags []string `json:"tags"`

		Field1 string `json:"1.3.6.1.4.1.11129.2.4.2"`
	} `json:"extensions"`

	FirstSeenDate int `json:"first_seen_date"`

	Issuer struct {
		C  string `json:"C"`
		CN string `json:"CN"`
		L  string `json:"L"`
		O  string `json:"O"`
		OU string `json:"OU"`
		ST string `json:"ST"`
	} `json:"issuer"`

	PublicKey struct {
		Algorithm string `json:"algorithm"`

		Rsa struct {
			Exponent string `json:"exponent"`
			KeySize  int    `json:"key_size"`
			Modulus  string `json:"modulus"`
		} `json:"rsa"`

		Dsa struct {
			P   string `json:"p"`
			Q   string `json:"q"`
			G   string `json:"g"`
			Pub string `json:"pub"`
		} `json:"dsa"`

		Ec struct {
			Oid string `json:"oid"`
			Pub string `json:"pub"`
		} `json:"ec"`
	} `json:"public_key"`

	Thumbprint       string `json:"thumbprint"`
	ThumbprintSha256 string `json:"thumbprint_sha256"`

	Validity struct {
		NotAfter  string `json:"not_after"`
		NotBefore string `json:"not_before"`
	} `json:"validity"`

	Version string `json:"version"`
}

// VTDomainScanBody https://developers.virustotal.com/reference/domains-1
type VTDomainScanBody struct {
	Data struct {
		Type string `json:"type"`
		Id   string `json:"id"`

		Attributes struct {
			// identity
			Whois                string            `json:"whois"`
			Tags                 []string          `json:"tags"`
			JARM                 string            `json:"jarm"`
			WhoisDate            int               `json:"whois_date"`
			Registrar            string            `json:"registrar"`
			Tld                  string            `json:"tld"`
			LastModificationDate int               `json:"last_modification_date"`
			Categories           map[string]string `json:"categories"`

			// dns
			LastDnsRecords []struct {
				Type     string `json:"type"`
				Value    string `json:"value"`
				Ttl      int    `json:"ttl"`
				Priority int    `json:"priority,omitempty"`
				Rname    string `json:"rname,omitempty"`
				Retry    int    `json:"retry,omitempty"`
				Minimum  int    `json:"minimum,omitempty"`
				Refresh  int    `json:"refresh,omitempty"`
				Expire   int    `json:"expire,omitempty"`
				Serial   int    `json:"serial,omitempty"`
			} `json:"last_dns_records"`

			PopularityRanks map[string]struct {
				Category   string `json:"category"`
				Result     string `json:"result"`
				Method     string `json:"method"`
				EngineName string `json:"engine_name"`
			} `json:"popularity_ranks"`

			// analysis
			Reputation         int `json:"reputation"` // community votes
			LastAnalysisDate   int `json:"last_analysis_date"`
			LastDnsRecordsDate int `json:"last_dns_records_date"`
			LastAnalysisStats  struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			LastAnalysisResults map[string]struct {
				Category   string `json:"category"`
				Result     string `json:"result"`
				Method     string `json:"method"`
				EngineName string `json:"engine_name"`
			} `json:"last_analysis_results"` // analysis by security provider
			TotalVotes struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
		} `json:"attributes"`

		Links struct {
			Self string `json:"self"`
		} `json:"links"`
	} `json:"data"`
}

// VTURLScanBody https://developers.virustotal.com/reference/url-info
type VTURLScanBody struct {
	Data struct {
		Type string `json:"type"`
		ID   string `json:"id"`

		Retries int `json:"retries"`

		Attributes struct {
			Categories map[string]string `json:"categories"`

			Favicon struct {
				Dhash  string `json:"dhash"`
				RawMd5 string `json:"raw_md5"`
			} `json:"favicon"`

			FirstSubmissionDate int  `json:"first_submission_date"`
			HasContent          bool `json:"has_content"`

			HtmlMeta map[string][]string `json:"html_meta"`

			LastAnalysisDate    int `json:"last_analysis_date"`
			LastAnalysisResults map[string]struct {
				Category   string `json:"category"`
				Result     string `json:"result"`
				Method     string `json:"method"`
				EngineName string `json:"engine_name"`
			} `json:"last_analysis_results"`

			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Timeout    int `json:"timeout"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`

			LastFinalUrl                  string `json:"last_final_url"`
			LastHttpResponseCode          int    `json:"last_http_response_code"`
			LastHttpResponseContentLength int    `json:"last_http_response_content_length"`
			LastHttpResponseContentSha256 string `json:"last_http_response_content_sha256"`
			LastHttpResponseCookies       struct {
				PHPSESSID string `json:"PHPSESSID"`
				SameSite  string `json:"SameSite"`
				Cfduid    string `json:"__cfduid"`
				Sessid    string `json:"sessid"`
			} `json:"last_http_response_cookies"`

			LastHttpResponseHeaders struct {
				CacheControl     string `json:"cache-control"`
				CfCacheStatus    string `json:"cf-cache-status"`
				CfRay            string `json:"cf-ray"`
				CfRequestId      string `json:"cf-request-id"`
				Connection       string `json:"connection"`
				ContentType      string `json:"content-type"`
				Date             string `json:"date"`
				Expires          string `json:"expires"`
				Pragma           string `json:"pragma"`
				Server           string `json:"server"`
				SetCookie        string `json:"set-cookie"`
				TransferEncoding string `json:"transfer-encoding"`
			} `json:"last_http_response_headers"`

			LastModificationDate int `json:"last_modification_date"`
			LastSubmissionDate   int `json:"last_submission_date"`

			Reputation int      `json:"reputation"`
			Tags       []string `json:"tags"`

			OutgoingLinks    []string          `json:"outgoing_links"`
			RedirectionChain []string          `json:"redirection_chain"`
			TargetedBrand    map[string]string `json:"targeted_brand"`
			TimesSubmitted   int               `json:"times_submitted"`
			Title            string            `json:"title"`
			TotalVotes       struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
			Trackers map[string]struct {
				Id        string `json:"id"`
				Timestamp int    `json:"timestamp"`
				Url       string `json:"url"`
			} `json:"trackers"`
			Url string `json:"url"`

			Date   int    `json:"date"`
			Status string `json:"status"`

			// analysis
			Stats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"stats"`
			Results map[string]struct {
				Category   string `json:"category"`
				Result     string `json:"result"`
				Method     string `json:"method"`
				EngineName string `json:"engine_name"`
			} `json:"results"`
		} `json:"attributes"`

		Links struct {
			Item string `json:"item"`
			Self string `json:"self"`
		} `json:"links"`
	} `json:"data"`
}

type VTErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}
