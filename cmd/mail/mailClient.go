package mail

import (
	"crypto/tls"
	"errors"
	"gopkg.in/gomail.v2"
	"log/slog"
)

type Client struct {
	isAvailable    bool
	config         ISMTPDynamicConfig
	dialer         *gomail.Dialer
	updateListener chan bool
}

type ISMTPDynamicConfig interface {
	IsSMTPEnabled() bool
	GetSMTPCredentials() (host, user, password string, port int, ssl bool, err error)

	SetSMTPConfig(host, user, password string, port int, ssl, enabled bool) error
}

func NewSMTPClient(config ISMTPDynamicConfig, updateChan chan bool) *Client {
	host, user, password, port, ssl, err := config.GetSMTPCredentials()

	client := Client{
		config:         config,
		updateListener: updateChan,
		dialer:         gomail.NewDialer(host, port, user, password),
	}

	client.dialer.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	client.dialer.SSL = ssl
	client.isAvailable = err == nil

	go client.ListenConfigUpdates()

	return &client
}

func (client *Client) ListenConfigUpdates() {
	slog.Info("smtp config change listener started")

	for {
		msg := <-client.updateListener
		if msg == true {
			slog.Info("smtp config updated")

			if !client.config.IsSMTPEnabled() {
				client.isAvailable = false
				return
			}

			host, user, password, port, ssl, err := client.config.GetSMTPCredentials()
			if err != nil {
				client.isAvailable = false
				return
			}

			client.dialer = gomail.NewDialer(host, port, user, password)
			client.dialer.SSL = ssl
			client.dialer.TLSConfig = &tls.Config{InsecureSkipVerify: true}

			client.isAvailable = true
		} else {
			slog.Warn("smtp config change listener stopped")
			break
		}
	}
}

func (client *Client) IsAvailable() bool {
	return client.isAvailable
}

func (client *Client) SendMessage(to, cc []string, subject, body string) error {
	if to == nil {
		return errors.New("receivers' addresses not defined")
	}

	message := gomail.NewMessage()

	message.SetHeader("From", client.dialer.Username)
	message.SetHeader("To", to...)

	message.SetHeader("Subject", subject)
	message.SetBody("text/html", body)

	err := client.dialer.DialAndSend(message)
	if err != nil {
		slog.Error("failed to send email: " + err.Error())
		return err
	}

	return nil
}
