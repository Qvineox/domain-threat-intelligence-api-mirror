package configs

import (
	"errors"
	"github.com/spf13/viper"
	"log/slog"
	"os"
	"path/filepath"
)

type DynamicConfig struct {
	config *viper.Viper
}

func NewDynamicConfig() (*DynamicConfig, error) {
	slog.Info("loading dynamic configuration...")

	var dynamic = &DynamicConfig{config: viper.New()}

	currentDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(currentDir, "configs")

	dynamic.config.SetConfigName("dynamic")
	dynamic.config.SetConfigType("json")

	dynamic.config.AddConfigPath(path)

	// find dy
	err = dynamic.config.ReadInConfig()
	if err != nil {
		_, ok := err.(viper.ConfigFileNotFoundError)
		if ok {
			slog.Warn("dynamic file not found, creating default config...")

			// setting default config
			err = dynamic.SetDefaultValues()
			if err != nil {
				return nil, err
			}

			file, err := os.Create(filepath.Join(path, "dynamic.json"))
			if err != nil {
				return nil, err
			}

			dynamic.config.SetConfigFile(file.Name())

			err = dynamic.config.WriteConfig()
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}

		if errors.Is(err, viper.ConfigFileNotFoundError{}) {
			slog.Error("dynamic file not found")
		}
	}

	slog.Info("dynamic configuration loaded")
	return dynamic, nil
}

func (c *DynamicConfig) GetValue(key DynamicVariables) (string, error) {
	if !c.config.IsSet(string(key)) {
		return "", errors.New("config value not set")
	}

	value := c.config.Get(string(key))

	parsed, ok := value.(string)
	if ok {
		if len(parsed) == 0 {
			return "", errors.New("config value empty")
		}

		return parsed, nil
	}

	return "", errors.New("malformed dynamic config value")
}

func (c *DynamicConfig) SetDefaultValues() error {
	c.config.SetDefault(string(NaumenClientKey), "")

	return nil
}

type DynamicVariables string

const (
	NaumenClientKey DynamicVariables = "naumen_client_key"
)
