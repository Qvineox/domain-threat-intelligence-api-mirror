package configs

import (
	"github.com/ilyakaznacheev/cleanenv"
	"os"
	"path/filepath"
)

type Config struct {
	Database struct {
		Host     string `env-required:"true" env:"db_host" json:"host"`
		Port     uint64 `env-required:"true" env:"db_port" json:"port"`
		User     string `env-required:"true" env:"db_user" json:"user"`
		Password string `env-required:"true" env:"db_pass" json:"password"`
		Name     string `env-required:"true" env:"db_name" json:"name"`
		Timezone string `env-required:"true" env:"db_timezone" json:"timezone"`
	} `env-required:"true" json:"database"`

	WebServer struct {
		Host    string `env-required:"true" env:"http_host" json:"host"`
		Port    uint64 `env-required:"true" env:"http_port" json:"port"`
		Swagger bool   `env-default:"false" env:"http_swagger" json:"swagger"`
	} `env-required:"true" json:"web_server"`

	Logging struct {
		Level string `env-default:"info" env:"log_level" json:"level"`
	} `json:"log"`
}

func ReadConfig() (Config, error) {
	var cfg Config

	currentDir, err := os.Getwd()
	if err != nil {
		return Config{}, err
	}

	err = cleanenv.ReadConfig(filepath.Join(currentDir, "configs", "config.json"), &cfg)
	if err != nil {
		return Config{}, err
	}

	return cfg, nil
}
