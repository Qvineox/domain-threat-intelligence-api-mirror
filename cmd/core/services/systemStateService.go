package services

import (
	"domain_threat_intelligence_api/configs"
)

type SystemStateServiceImpl struct {
	dynamicConfig *configs.DynamicConfigProvider
}

func NewSystemStateServiceImpl(dynamicConfig *configs.DynamicConfigProvider) *SystemStateServiceImpl {
	return &SystemStateServiceImpl{dynamicConfig: dynamicConfig}
}

func (s *SystemStateServiceImpl) RetrieveDynamicConfig() ([]byte, error) {
	return s.dynamicConfig.GetCurrentState()
}

func (s *SystemStateServiceImpl) ReturnToDefault() error {
	return s.dynamicConfig.SetDefaultValues()
}
