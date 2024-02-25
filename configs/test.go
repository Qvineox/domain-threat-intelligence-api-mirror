package configs

import (
	"github.com/ilyakaznacheev/cleanenv"
)

type TestConfig struct {
	Database struct {
		Host     string `env-required:"true" env:"db_host" json:"host"`
		Port     uint64 `env-required:"true" env:"db_port" json:"port"`
		User     string `env-required:"true" env:"db_user" json:"user"`
		Password string `env-required:"true" env:"db_pass" json:"password"`
		Name     string `env-required:"true" env:"db_name" json:"name"`
		Timezone string `env-required:"true" env:"db_timezone" json:"timezone"`
	} `json:"database"`
}

func NewTestConfig() (TestConfig, error) {
	var cfg TestConfig

	// currentDir, err := os.Getwd()
	// if err != nil {
	// 	return TestConfig{}, err
	// }

	// if config file not find tries to get configuration parameters from environment
	err := cleanenv.ReadConfig("../configs/config.test.static.json", &cfg)
	if err != nil {
		err = cleanenv.ReadEnv(&cfg)
		if err != nil {
			return TestConfig{}, err
		}
	}

	return cfg, nil
}
