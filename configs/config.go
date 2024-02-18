package configs

import (
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/spf13/viper"
	"log/slog"
	"os"
	"path/filepath"
)

type StaticConfigV struct {
	config *viper.Viper
}

type StaticConfig struct {
	Database struct {
		Host     string `env-required:"true" env:"db_host" json:"host"`
		Port     uint64 `env-required:"true" env:"db_port" json:"port"`
		User     string `env-required:"true" env:"db_user" json:"user"`
		Password string `env-required:"true" env:"db_pass" json:"password"`
		Name     string `env-required:"true" env:"db_name" json:"name"`
		Timezone string `env-required:"true" env:"db_timezone" json:"timezone"`
	} `json:"database"`

	WebServer struct {
		Host string `env-required:"true" env:"http_host" json:"host"`
		Port uint64 `env-required:"true" env:"http_port" json:"port"`

		API struct {
			Path string `env-default:"/api/v1" env:"http_api_path" json:"path"`
		}

		Swagger struct {
			Enabled bool   `env-default:"false" env:"http_swagger_enabled" json:"enabled"`
			Host    string `env-default:"localhost:7090" env:"http_swagger_host" json:"host"`
			Version string `env-default:"v0.0.1" env:"http_swagger_version" json:"version"`
		} `json:"swagger"`

		Security struct {
			UseTLS         bool     `env:"http_security_tls" json:"tls"`
			AllowedOrigins []string `env:"http_security_origins" json:"origins"`
			Domain         string   `env:"http_security_domain" json:"domain"`
		} `json:"security"`
	} `json:"http"`

	Logging struct {
		Level string `env-default:"info" env:"log_level" json:"level"`
	} `json:"log"`
}

func NewStaticConfig() (StaticConfig, error) {
	slog.Info("loading static configuration...")

	var cfg StaticConfig

	currentDir, err := os.Getwd()
	if err != nil {
		return StaticConfig{}, err
	}

	// if config file not find tries to get configuration parameters from environment
	err = cleanenv.ReadConfig(filepath.Join(currentDir, "configs", "config.static.json"), &cfg)
	if err != nil {
		slog.Warn("config file not found, reading environment...")
		err = cleanenv.ReadEnv(&cfg)
		if err != nil {
			return StaticConfig{}, err
		}
	}

	slog.Info("static configuration loaded")
	return cfg, nil
}
