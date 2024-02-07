package configs

import (
	"encoding/json"
	"errors"
	"github.com/fsnotify/fsnotify"
	"github.com/ilyakaznacheev/cleanenv"
	"log"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
)

type DynamicConfigProvider struct {
	config dynamicConfig
	path   string
}

type dynamicConfig struct {
	SMTP         smtpConfig         `env-required:"false" json:"SMTP"`
	Integrations integrationsConfig `end-required:"false" json:"Integrations"`
}

type smtpConfig struct {
}

type integrationsConfig struct {
	Naumen naumenConfig `env-required:"false" json:"Naumen"`
}

type naumenConfig struct {
	Enabled bool `env-default:"false" json:"Enabled"`

	ClientGroupID uint64 `json:"ClientGroupID"`
	ClientID      uint64 `json:"ClientID"`
	ClientKey     string `json:"ClientKey"`
	Url           string `json:"URL"`

	BlacklistsService struct {
		AgreementID uint64   `json:"AgreementID"`
		Slm         uint64   `json:"SLM"`
		CallType    string   `json:"CallType"`
		Types       []string `json:"Types"`
	} `json:"BlacklistsService"`
}

// NewDynamicConfigProvider creates or reads dynamic configuration. If dynamic file exists, recovers values or creates new file.
func NewDynamicConfigProvider() (*DynamicConfigProvider, error) {
	slog.Info("loading dynamic configuration...")
	var provider = DynamicConfigProvider{
		config: dynamicConfig{},
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	provider.path = filepath.Join(currentDir, "configs", "config.dynamic.json")

	err = cleanenv.ReadConfig(provider.path, &provider.config)
	if err == nil {
		return &provider, err
	}

	// check if file not found
	var pathErr *os.PathError
	ok := errors.As(err, &pathErr)
	if !ok {
		return nil, err
	}

	slog.Warn("dynamic config file missing, creating...")

	_, err = os.Create(provider.path)
	if err != nil {
		slog.Error("failed to create dynamic config file: " + err.Error())
		return nil, err
	}

	// fill file with default values
	_ = provider.SetDefaultValues()
	err = provider.WriteToFile()
	if err != nil {
		return nil, err
	}

	return &provider, err
}

func (d *DynamicConfigProvider) StartWatcher() {
	slog.Info("starting dynamic config watcher...")

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("failed to start dynamic config watcher: " + err.Error())
	}

	err = watcher.Add(d.path)
	if err != nil {
		log.Fatal(err)
	}

	defer watcher.Close()

	for {
		select {
		case err, ok := <-watcher.Errors:
			if !ok {
				slog.Warn("watcher closed")
				return
			}

			slog.Error("watcher error: " + err.Error())
		// Read from Events.
		case e, ok := <-watcher.Events:
			if !ok {
				slog.Warn("watcher closed")
				return
			}

			switch e.Op {
			case fsnotify.Write:
				slog.Warn("dynamic configuration file changed, updating...")

				bytes_, err := os.ReadFile(d.path)
				if err != nil {
					slog.Error("failed to read file: " + err.Error())
				} else {
					err = json.Unmarshal(bytes_, &d.config)
					if err != nil {
						slog.Error("failed to decode file: " + err.Error())
					}
				}
			default:
				slog.Debug("unhandled dynamic configuration event: " + e.String())
			}
		}
	}
}

func (d *DynamicConfigProvider) WriteToFile() error {
	bytes_, err := json.Marshal(d.config)
	if err != nil {
		slog.Error("failed to encode dynamic config: " + err.Error())
		return err
	}

	err = os.WriteFile(d.path, bytes_, 0700)
	if err != nil {
		slog.Error("failed to write dynamic config: " + err.Error())
		return err
	}

	return nil
}

func (d *DynamicConfigProvider) GetCurrentState() ([]byte, error) {
	bytes, err := json.Marshal(d.config)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func (d *DynamicConfigProvider) SetDefaultValues() error {
	d.config.SMTP = smtpConfig{}
	d.config.Integrations = integrationsConfig{}

	err := d.WriteToFile()
	if err != nil {
		return err
	}

	return nil
}

func (d *DynamicConfigProvider) IsNaumenEnabled() bool {
	return d.config.Integrations.Naumen.Enabled
}

func (d *DynamicConfigProvider) GetNaumenCredentials() (url, key string, uID, gID uint64, err error) {
	if !d.IsNaumenEnabled() {
		return "", "", 0, 0, errors.New("service desk integration disabled")
	}

	n := d.config.Integrations.Naumen

	if len(n.Url) == 0 || len(n.ClientKey) == 0 || n.ClientID == 0 || n.ClientGroupID == 0 {
		return "", "", 0, 0, errors.New("service desk configuration incomplete")
	}

	return n.Url, n.ClientKey, n.ClientID, n.ClientGroupID, nil
}

func (d *DynamicConfigProvider) SetNaumenConfig(enabled bool, host, key string, uID, gID uint64) (err error) {
	if len(key) == 0 || len(host) == 0 || uID == 0 || gID == 0 {
		return errors.New("service desk configuration incomplete")
	}

	_, err = url.Parse(host)
	if err != nil {
		return errors.New("host malformed: " + err.Error())
	}

	d.config.Integrations.Naumen.Enabled = enabled

	d.config.Integrations.Naumen.ClientGroupID = uID
	d.config.Integrations.Naumen.ClientID = gID
	d.config.Integrations.Naumen.ClientKey = key

	d.config.Integrations.Naumen.Url = host

	err = d.WriteToFile()
	if err != nil {
		return err
	}

	return nil
}

func (d *DynamicConfigProvider) SetNaumenBlacklistServiceConfig(aID, slm uint64, callType string, types []string) (err error) {
	if len(callType) == 0 || len(types) == 0 || aID == 0 || slm == 0 {
		return errors.New("service desk configuration incomplete")
	}

	d.config.Integrations.Naumen.BlacklistsService.AgreementID = aID
	d.config.Integrations.Naumen.BlacklistsService.Slm = slm
	d.config.Integrations.Naumen.BlacklistsService.CallType = callType
	d.config.Integrations.Naumen.BlacklistsService.Types = types

	err = d.WriteToFile()
	if err != nil {
		return err
	}

	return nil
}

func (d *DynamicConfigProvider) GetBlacklistServiceConfig() (aID, slm uint64, callType string, types []string, err error) {
	if !d.IsNaumenEnabled() {
		return 0, 0, "", nil, errors.New("service desk integration disabled")
	}

	s := d.config.Integrations.Naumen.BlacklistsService

	if s.Slm == 0 || s.AgreementID == 0 || len(s.CallType) == 0 || len(s.Types) == 0 {
		return 0, 0, "", nil, errors.New("service desk configuration incomplete")
	}

	return s.AgreementID, s.Slm, s.CallType, s.Types, nil
}
