package systemStateEntities

type DynamicConfigState struct {
	NaumenClientKey string `mapstructure:"naumen_client_key" json:"Naumen.Client.Key"`
	NaumenClientID  string `mapstructure:"naumen_client_id" json:"Naumen.Client.ID" `

	SMTPHost     string `mapstructure:"smtp_host" json:"SMTP.Host"`
	SMTPUser     string `mapstructure:"smtp_user" json:"SMTP.User"`
	SMTPSender   string `mapstructure:"smtp_sender" json:"SMTP.Sender"`
	SMTPPassword string `mapstructure:"smtp_password" json:"SMTP.Password"`
	SMTPUseTLS   bool   `mapstructure:"smtp_use_tls" json:"SMTP.UseTLS"`
}
