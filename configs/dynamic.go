package configs

import (
	"domain_threat_intelligence_api/cmd/core/entities/systemStateEntities"
	"encoding/json"
	"errors"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
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
			slog.Error("dynamic file not found!")
		}
	}

	slog.Info("dynamic configuration loaded.")

	dynamic.config.OnConfigChange(func(e fsnotify.Event) {
		slog.Warn("dynamic config changed.")
	})

	dynamic.config.WatchConfig()

	slog.Info("started config watcher")

	return dynamic, nil
}

func (c *DynamicConfig) GetVariable(key DynamicVariables) (string, error) {
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
	c.config.SetDefault(string(NaumenClientID), "")

	c.config.SetDefault(string(SMTPHost), "")
	c.config.SetDefault(string(SMTPUser), "")
	c.config.SetDefault(string(SMTPSender), "dti")
	c.config.SetDefault(string(SMTPPassword), "")
	c.config.SetDefault(string(SMTPUseTLS), "false")

	return nil
}

func (c *DynamicConfig) SetValue(key string, value string) error {

	switch key {
	case string(NaumenClientKey):
		c.config.Set(string(NaumenClientKey), value)
	case string(NaumenClientID):
		c.config.Set(string(NaumenClientID), value)
	case string(SMTPHost):
		c.config.Set(string(SMTPHost), value)
	case string(SMTPUser):
		c.config.Set(string(SMTPUser), value)
	case string(SMTPSender):
		c.config.Set(string(SMTPSender), value)
	case string(SMTPPassword):
		c.config.Set(string(SMTPPassword), value)
	case string(SMTPUseTLS):
		c.config.Set(string(SMTPUseTLS), value)
	default:
		return errors.New("configuration parameter not found")
	}

	return nil
}

func (c *DynamicConfig) GetCurrentState() ([]byte, error) {
	var config systemStateEntities.DynamicConfigState

	settings := c.config.AllSettings()
	slog.Info(strconv.Itoa(len(settings)))

	bytes, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}

	err = c.config.Unmarshal(&config)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

type DynamicVariables string

const (
	NaumenClientKey DynamicVariables = "integrations.naumen.client_key"
	NaumenClientID  DynamicVariables = "integrations.naumen.client_id"
	SMTPHost        DynamicVariables = "smtp.host"
	SMTPUser        DynamicVariables = "smtp.user"
	SMTPSender      DynamicVariables = "smtp.sender"
	SMTPPassword    DynamicVariables = "smtp.password"
	SMTPUseTLS      DynamicVariables = "smtp.use_tls"
)
