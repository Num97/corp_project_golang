package main

import (
	"encoding/json"
	"fmt"
	"net/smtp"
	"os"
)

type ConfigSMTP struct {
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     string `json:"smtp_port"`
	AuthEmail    string `json:"auth_email"`
	AuthPassword string `json:"auth_password"`
	UseAuth      bool   `json:"use_auth"`
}

type Mailer struct {
	Config ConfigSMTP
}

func LoadConfig(filename string) (ConfigSMTP, error) {
	file, err := os.Open(filename)
	if err != nil {
		return ConfigSMTP{}, err
	}
	defer file.Close()

	var config ConfigSMTP
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return ConfigSMTP{}, err
	}

	return config, nil
}

func NewMailer(config ConfigSMTP) *Mailer {
	return &Mailer{Config: config}
}

func (m *Mailer) SendMail(to, login, password string) error {
	subject := "Доступ к корпоративному порталу"
	body := fmt.Sprintf("Ваш логин: %s\nВаш пароль: %s", login, password)
	header := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n", m.Config.AuthEmail, to, subject)
	msg := []byte(header + body)

	var auth smtp.Auth
	if m.Config.UseAuth {
		auth = smtp.PlainAuth("", m.Config.AuthEmail, m.Config.AuthPassword, m.Config.SMTPHost)
	}

	err := smtp.SendMail(m.Config.SMTPHost+":"+m.Config.SMTPPort, auth, m.Config.AuthEmail, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("ошибка отправки письма: %v", err)
	}
	return nil
}
