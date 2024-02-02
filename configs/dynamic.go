package configs

import (
	"encoding/json"
	"errors"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

func (c *DynamicConfig) GetNaumenURL() (url string, err error) {
	url = c.config.GetString(string(NaumenURL))

	if len(url) == 0 {
		return "", errors.New("url not defined")
	}

	return url, nil
}

func (c *DynamicConfig) GetNaumenBlacklistService() (id, slm int, callType string, err error) {
	id = c.config.GetInt(string(NaumenBlacklistsAgreementID))
	slm = c.config.GetInt(string(NaumenBlacklistsSLM))
	callType = c.config.GetString(string(NaumenBlacklistsCallType))

	if id == 0 || slm == 0 || len(callType) == 0 {
		return 0, 0, "", errors.New("service params not defined")
	}

	return id, slm, callType, nil
}

func (c *DynamicConfig) GetNaumenBlacklistTypes() (types []string, err error) {
	types = c.config.GetStringSlice(string(NaumenBlacklistsTypes))

	if len(types) == 0 {
		return nil, errors.New("types to blacklist not defined")
	}

	return types, nil
}

func (c *DynamicConfig) GetNaumenCredentials() (clientKey, clientID, clientGroupID string, err error) {
	clientKey = c.config.GetString(string(NaumenClientKey))
	clientID = c.config.GetString(string(NaumenClientID))
	clientGroupID = c.config.GetString(string(NaumenClientGroupID))

	if len(clientKey) == 0 || len(clientID) == 0 || len(clientGroupID) == 0 {
		return "", "", clientGroupID, errors.New("credentials not defined")
	}

	return clientKey, clientID, clientGroupID, nil
}

func (c *DynamicConfig) GetSMTPCredentials() (host, user, password, sender string, useTLS bool, err error) {
	host = c.config.GetString(string(SMTPHost))

	if len(host) == 0 {
		return "", "", "", "", false, errors.New("smtp host not defined")
	}

	user = c.config.GetString(string(SMTPUser))
	password = c.config.GetString(string(SMTPPassword))

	sender = c.config.GetString(string(SMTPSender))

	useTLS = c.config.GetBool(string(SMTPUseTLS))

	return host, user, password, sender, useTLS, nil
}

func (c *DynamicConfig) SetDefaultValues() error {
	c.config.SetDefault(string(NaumenURL), "")
	c.config.SetDefault(string(NaumenClientKey), "")
	c.config.SetDefault(string(NaumenClientID), "")
	c.config.SetDefault(string(NaumenClientGroupID), "")

	// blacklists service parameters
	c.config.SetDefault(string(NaumenBlacklistsAgreementID), "")
	c.config.SetDefault(string(NaumenBlacklistsSLM), "")
	c.config.SetDefault(string(NaumenBlacklistsCallType), "")
	c.config.SetDefault(string(NaumenBlacklistsTypes), []string{"ip"})

	// smtp credentials
	c.config.SetDefault(string(SMTPHost), "")
	c.config.SetDefault(string(SMTPUser), "")
	c.config.SetDefault(string(SMTPSender), "dti")
	c.config.SetDefault(string(SMTPPassword), "")
	c.config.SetDefault(string(SMTPUseTLS), "false")

	return nil
}

func (c *DynamicConfig) SetValue(key string, value string) error {

	switch key {
	case string(NaumenURL):
		c.config.Set(string(NaumenURL), value)
	case string(NaumenClientKey):
		c.config.Set(string(NaumenClientKey), value)
	case string(NaumenClientGroupID):
		c.config.Set(string(NaumenClientGroupID), value)
	case string(NaumenClientID):
		c.config.Set(string(NaumenClientID), value)
	case string(NaumenBlacklistsAgreementID):
		c.config.Set(string(NaumenBlacklistsAgreementID), value)
	case string(NaumenBlacklistsSLM):
		c.config.Set(string(NaumenBlacklistsSLM), value)
	case string(NaumenBlacklistsCallType):
		c.config.Set(string(NaumenBlacklistsCallType), value)
	case string(NaumenBlacklistsTypes):
		values := strings.Split(value, ",")
		if len(values) == 0 {
			return errors.New("blacklisting types not defined")
		}

		c.config.Set(string(NaumenBlacklistsTypes), values)
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

	err := c.config.WriteConfig()
	if err != nil {
		return err
	}

	return nil
}

func (c *DynamicConfig) GetCurrentState() ([]byte, error) {
	settings := c.config.AllSettings()
	slog.Info(strconv.Itoa(len(settings)))

	bytes, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

type DynamicVariables string

const (
	NaumenURL                   DynamicVariables = "integrations.naumen.url"
	NaumenClientKey             DynamicVariables = "integrations.naumen.client_key"
	NaumenClientID              DynamicVariables = "integrations.naumen.client_id"
	NaumenClientGroupID         DynamicVariables = "integrations.naumen.client_group_id"
	NaumenBlacklistsAgreementID DynamicVariables = "integrations.naumen.blacklists.agreement_id"
	NaumenBlacklistsSLM         DynamicVariables = "integrations.naumen.blacklists.slm"
	NaumenBlacklistsCallType    DynamicVariables = "integrations.naumen.blacklists.call_type"
	NaumenBlacklistsTypes       DynamicVariables = "integrations.naumen.blacklists.types"
	SMTPHost                    DynamicVariables = "smtp.host"
	SMTPUser                    DynamicVariables = "smtp.user"
	SMTPSender                  DynamicVariables = "smtp.sender"
	SMTPPassword                DynamicVariables = "smtp.password"
	SMTPUseTLS                  DynamicVariables = "smtp.use_tls"
)
