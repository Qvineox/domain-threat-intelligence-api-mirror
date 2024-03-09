package agentEntities

import "domain_threat_intelligence_api/api/grpc/protoServices"

// ScanAgentConfig defines configuration parameters used in Agent.
type ScanAgentConfig struct {
	HasNMAP bool `json:"HasNMAP"`

	// APIKeys in agents are stored in memory. TODO: Refer to Agent local data or database key store.
	APIKeys map[OSSProvider]string `json:"-" gorm:"-"`
}

type OSSProvider uint64

const (
	OSS_PROVIDER_VIRUS_TOTAL OSSProvider = iota
	OSS_PROVIDER_IP_QUALITY_SCORE
	OSS_PROVIDER_CROWD_SEC
	OSS_PROVIDER_SHODAN
	OSS_PROVIDER_IP_WHO_IS
)

func (c *ScanAgentConfig) GetProtoAPIKeys() (protoKeys []*protoServices.ProviderAPIKey) {
	for provider, apiKey := range c.APIKeys {
		protoKeys = append(protoKeys, &protoServices.ProviderAPIKey{
			Provider: protoServices.OSSProvider(provider),
			APIKey:   apiKey,
		})
	}

	return protoKeys
}
