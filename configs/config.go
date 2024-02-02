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
	} `env-required:"true" json:"database"`

	WebServer struct {
		Host          string `env-required:"true" env:"http_host" json:"host"`
		Port          uint64 `env-required:"true" env:"http_port" json:"port"`
		Swagger       bool   `env-default:"false" env:"http_swagger" json:"swagger"`
		AllowedOrigin string `env-required:"false" env:"http_origin" json:"allowed_origin"`
	} `env-required:"true" json:"web_server"`

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
	err = cleanenv.ReadConfig(filepath.Join(currentDir, "configs", "config.json"), &cfg)
	if err != nil {
		err = cleanenv.ReadEnv(&cfg)

		return StaticConfig{}, err
	}

	slog.Info("static configuration loaded")
	return cfg, nil
}
