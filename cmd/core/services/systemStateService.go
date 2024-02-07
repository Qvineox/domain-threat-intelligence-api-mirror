package services

import (
	"domain_threat_intelligence_api/configs"
)

type SystemStateServiceImpl struct {
	dynamicConfig *configs.DynamicConfigProvider
}

func (s *SystemStateServiceImpl) UpdateSMTPConfig(enabled bool, host, user, password, sender string, useTLS bool) error {
	s.dynamicConfig.SetSMTPAvailability(enabled)

	err := s.dynamicConfig.SetSMTPCredentials(host, user, password, sender, useTLS)
	if err != nil {
		return err
	}

	return nil
}

func (s *SystemStateServiceImpl) UpdateNSDCredentials(enabled bool, url, clientID, clientGroupID, clientKey string) error {
	s.dynamicConfig.SetNaumenAvailability(enabled)

	err := s.dynamicConfig.SetNaumenCredentials(url, clientKey, clientID, clientGroupID)
	if err != nil {
		return err
	}

	return nil
}

func (s *SystemStateServiceImpl) UpdateNSDBlacklistServiceConfig(id, slm int, callType string, types []string) error {
	err := s.dynamicConfig.SetNaumenBlacklistConfig(id, slm, callType, types)
	if err != nil {
		return err
	}

	return nil
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
