package configs

import (
	"encoding/json"
	"errors"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
)

type DynamicConfigProvider struct {
	config *viper.Viper

	//smtpServiceHook func()
}

func NewDynamicConfig() (*DynamicConfigProvider, error) {
	slog.Info("loading dynamic configuration...")

	var dynamic = &DynamicConfigProvider{config: viper.New()}

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
		slog.Warn("dynamic config changed, updating...")
	})

	dynamic.config.WatchConfig()

	slog.Info("started config watcher")

	return dynamic, nil
}

func (c *DynamicConfigProvider) IsNaumenEnabled() (enabled bool) {
	return c.config.GetBool(NaumenEnabled)
}

func (c *DynamicConfigProvider) GetNaumenBlacklistService() (id, slm int, callType string, err error) {
	id = c.config.GetInt(NaumenBlacklistsAgreementID)
	slm = c.config.GetInt(NaumenBlacklistsSLM)
	callType = c.config.GetString(NaumenBlacklistsCallType)

	if id == 0 || slm == 0 || len(callType) == 0 {
		return 0, 0, "", errors.New("service params not defined")
	}

	return id, slm, callType, nil
}

func (c *DynamicConfigProvider) GetNaumenBlacklistTypes() (types []string, err error) {
	types = c.config.GetStringSlice(NaumenBlacklistsTypes)

	if len(types) == 0 {
		return nil, errors.New("types to blacklist not defined")
	}

	return types, nil
}

func (c *DynamicConfigProvider) GetNaumenCredentials() (url, clientKey, clientID, clientGroupID string, err error) {
	if !c.config.GetBool(NaumenEnabled) {
		return "", "", "", clientGroupID, errors.New("naumen service desk disabled")
	}

	url = c.config.GetString(NaumenURL)

	if len(url) == 0 {
		return "", "", "", clientGroupID, errors.New("credentials not defined")
	}

	clientKey = c.config.GetString(NaumenClientKey)
	clientID = c.config.GetString(NaumenClientID)
	clientGroupID = c.config.GetString(NaumenClientGroupID)

	if len(clientKey) == 0 || len(clientID) == 0 || len(clientGroupID) == 0 {
		return "", "", "", clientGroupID, errors.New("credentials not defined")
	}

	return url, clientKey, clientID, clientGroupID, nil
}

func (c *DynamicConfigProvider) SetNaumenAvailability(enabled bool) {
	c.config.SetDefault(NaumenEnabled, enabled)
}

func (c *DynamicConfigProvider) SetNaumenCredentials(serviceUrl, clientKey, clientID, clientGroupID string) error {
	if len(serviceUrl) == 0 || len(clientKey) == 0 || len(clientID) == 0 || len(clientGroupID) == 0 {
		return errors.New("one out of required parameters not defined")
	}

	_, err := url.Parse(serviceUrl)
	if err != nil {
		return errors.New("url parsing error: " + err.Error())
	}

	c.config.SetDefault(NaumenURL, serviceUrl)
	c.config.SetDefault(NaumenClientKey, clientKey)
	c.config.SetDefault(NaumenClientID, clientID)
	c.config.SetDefault(NaumenClientGroupID, clientGroupID)

	return c.config.WriteConfig()
}

func (c *DynamicConfigProvider) SetNaumenBlacklistConfig(id, slm int, callType string, types []string) error {
	if id == 0 || slm == 0 || len(callType) == 0 || len(types) == 0 {
		return errors.New("one out of required parameters not defined")
	}

	c.config.SetDefault(NaumenBlacklistsAgreementID, id)
	c.config.SetDefault(NaumenBlacklistsSLM, slm)
	c.config.SetDefault(NaumenBlacklistsCallType, callType)
	c.config.SetDefault(NaumenBlacklistsTypes, types)

	return nil
}

func (c *DynamicConfigProvider) GetSMTPCredentials() (host, user, password, sender string, useTLS bool, err error) {
	if !c.config.GetBool(SMTPEnabled) {
		return "", "", "", "", false, errors.New("smtp service disabled")
	}

	host = c.config.GetString(SMTPHost)

	if len(host) == 0 {
		return "", "", "", "", false, errors.New("smtp host not defined")
	}

	user = c.config.GetString(SMTPUser)
	password = c.config.GetString(SMTPPassword)

	sender = c.config.GetString(SMTPSender)

	useTLS = c.config.GetBool(SMTPUseTLS)

	return host, user, password, sender, useTLS, nil
}

func (c *DynamicConfigProvider) SetSMTPAvailability(enabled bool) {
	c.config.SetDefault(SMTPEnabled, enabled)
}

func (c *DynamicConfigProvider) SetSMTPCredentials(host, user, password, sender string, useTLS bool) (err error) {
	if len(host) == 0 || len(user) == 0 || len(sender) == 0 {
		return errors.New("one out of required parameters not defined")
	}

	c.config.SetDefault(SMTPHost, host)
	c.config.SetDefault(SMTPUser, user)
	c.config.SetDefault(SMTPSender, sender)
	c.config.SetDefault(SMTPUseTLS, useTLS)

	if len(password) > 0 {
		c.config.SetDefault(SMTPPassword, password)
	}

	slog.Info("overriding SMTP configuration...")
	return c.config.WriteConfig()
}

func (c *DynamicConfigProvider) SetDefaultValues() error {
	c.config.SetDefault(NaumenEnabled, false)
	c.config.SetDefault(NaumenURL, "")
	c.config.SetDefault(NaumenClientKey, "")
	c.config.SetDefault(NaumenClientID, "")
	c.config.SetDefault(NaumenClientGroupID, "")

	// blacklists service parameters
	c.config.SetDefault(NaumenBlacklistsAgreementID, "")
	c.config.SetDefault(NaumenBlacklistsSLM, "")
	c.config.SetDefault(NaumenBlacklistsCallType, "")
	c.config.SetDefault(NaumenBlacklistsTypes, []string{})

	// smtp credentials
	c.config.SetDefault(SMTPEnabled, false)
	c.config.SetDefault(SMTPHost, "")
	c.config.SetDefault(SMTPUser, "")
	c.config.SetDefault(SMTPSender, "")
	c.config.SetDefault(SMTPPassword, "")
	c.config.SetDefault(SMTPUseTLS, false)

	return nil
}

func (c *DynamicConfigProvider) GetCurrentState() ([]byte, error) {
	settings := c.config.AllSettings()
	slog.Info(strconv.Itoa(len(settings)))

	bytes, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

const (
	NaumenEnabled               string = "integrations.naumen.enabled"
	NaumenURL                          = "integrations.naumen.url"
	NaumenClientKey                    = "integrations.naumen.clientKey"
	NaumenClientID                     = "integrations.naumen.clientID"
	NaumenClientGroupID                = "integrations.naumen.clientGroupID"
	NaumenBlacklistsAgreementID        = "integrations.naumen.blacklists.agreementID"
	NaumenBlacklistsSLM                = "integrations.naumen.blacklists.slm"
	NaumenBlacklistsCallType           = "integrations.naumen.blacklists.callType"
	NaumenBlacklistsTypes              = "integrations.naumen.blacklists.types"
	SMTPEnabled                        = "smtp.enabled"
	SMTPHost                           = "smtp.host"
	SMTPUser                           = "smtp.user"
	SMTPSender                         = "smtp.sender"
	SMTPPassword                       = "smtp.password"
	SMTPUseTLS                         = "smtp.useTLS"
)
