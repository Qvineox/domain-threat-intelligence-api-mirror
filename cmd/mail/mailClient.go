package mail

import (
	"crypto/tls"
	"errors"
	"gopkg.in/gomail.v2"
	"log/slog"
)

type Client struct {
	config ISMTPDynamicConfig

	dialer         *gomail.Dialer
	updateListener chan bool
}

type ISMTPDynamicConfig interface {
	IsSMTPEnabled() bool
	GetSMTPCredentials() (user, password string, err error)
	GetSMTPSettings() (host, from string, port int, ssl bool, err error)

	SetSMTPConfig(enabled, SSL, UseAuth bool, host, user, from, password string, port int) error
}

func NewSMTPClient(config ISMTPDynamicConfig, updateChan chan bool) *Client {
	host, _, port, ssl, err := config.GetSMTPSettings()
	if err != nil {
		slog.Warn("required smtp settings not provided. client not available.")
	}

	user, password, err := config.GetSMTPCredentials()
	if err != nil {
		slog.Warn("required smtp credentials not provided. client not available.")
	}

	client := Client{
		config:         config,
		updateListener: updateChan,
		dialer:         gomail.NewDialer(host, port, user, password),
	}

	client.dialer.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	client.dialer.SSL = ssl

	go client.ListenConfigUpdates()

	return &client
}

func (client *Client) ListenConfigUpdates() {
	slog.Info("smtp config change listener started")

	for {
		msg := <-client.updateListener
		if msg == true {
			slog.Info("smtp config update triggered")

			host, _, port, ssl, err := client.config.GetSMTPSettings()
			if err != nil {
				slog.Warn("required smtp settings not provided. client not available: " + err.Error())
				return
			}

			user, password, err := client.config.GetSMTPCredentials()
			if err != nil {
				slog.Warn("required smtp credentials not provided. client not available: " + err.Error())
				return
			}

			client.dialer = gomail.NewDialer(host, port, user, password)
			client.dialer.SSL = ssl
			client.dialer.TLSConfig = &tls.Config{InsecureSkipVerify: true}

			slog.Info("smtp config updated")
		} else {
			slog.Warn("smtp config change listener stopped")
			break
		}
	}
}

func (client *Client) SendMessage(to, cc, bcc []string, subject, body string) error {
	_, from, _, _, err := client.config.GetSMTPSettings()
	if err != nil {
		return err
	}

	if to == nil {
		slog.Warn("receiver address not defined")
		return errors.New("receivers' addresses not defined")
	}

	message := gomail.NewMessage()

	message.SetHeader("From", from)
	message.SetHeader("To", to...)
	message.SetHeader("Cc", cc...)
	message.SetHeader("Bcc", bcc...)

	message.SetHeader("Subject", subject)
	message.SetBody("text/html", body)

	err = client.dialer.DialAndSend(message)
	if err != nil {
		slog.Error("failed to send email: " + err.Error())
		return err
	}

	return nil
}
