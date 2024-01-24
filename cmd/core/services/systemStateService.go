package services

import (
	"domain_threat_intelligence_api/configs"
	"errors"
)

type SystemStateServiceImpl struct {
	dynamicConfig *configs.DynamicConfig
}

func NewSystemStateServiceImpl(dynamicConfig *configs.DynamicConfig) *SystemStateServiceImpl {
	return &SystemStateServiceImpl{dynamicConfig: dynamicConfig}
}

func (s *SystemStateServiceImpl) RetrieveDynamicConfig() ([]byte, error) {
	return s.dynamicConfig.GetCurrentState()
}

func (s *SystemStateServiceImpl) SaveDynamicConfigVariable(key, value string) error {
	if len(key) == 0 || len(value) == 0 {
		return errors.New("key or value not defined")
	}

	err := s.dynamicConfig.SetValue(key, value)
	if err != nil {
		return err
	}

	return nil
}

func (s *SystemStateServiceImpl) ReturnToDefault() error {
	return s.dynamicConfig.SetDefaultValues()
}
