package mailer

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	resend "github.com/resend/resend-go/v2"
	"github.com/vanng822/go-premailer/premailer"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

//go:generate mockgen -destination=./mailer_mock.go -package=mailer . Mailer
type Config struct {
	To           string
	Subject      string
	Html         string
	Text         string
	TemplateName string
	Data         any
	Tags         []string
	ReplyTo      string
}

type Mailer interface {
	SendMail(ctx context.Context, cfg Config) (string, error)
}

type resendMailer struct {
	client *resend.Client
	from   string
}

func NewMailer() Mailer {
	apiKey := os.Getenv("RESEND_API_KEY")
	from := os.Getenv("SENDER_EMAIL")
	if apiKey == "" || from == "" {
		panic("RESEND_API_KEY and SENDER_EMAIL are required env vars")
	}
	return &resendMailer{
		client: resend.NewClient(apiKey),
		from:   from,
	}
}

func (m *resendMailer) SendMail(ctx context.Context, cfg Config) (string, error) {
	if cfg.To == "" || cfg.Subject == "" {
		return "", errors.New("to and subject are required")
	}

	var cancel context.CancelFunc
	if _, has := ctx.Deadline(); !has {
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}

	html := strings.TrimSpace(cfg.Html)
	if html == "" && cfg.TemplateName != "" {
		var err error
		html, err = renderHTML(cfg.TemplateName, cfg.Data)
		if err != nil {
			return "", fmt.Errorf("render template: %w", err)
		}
	}

	if html != "" {
		inlined, err := inlineCSS(html)
		if err != nil {
			return "", fmt.Errorf("inline css: %w", err)
		}
		html = inlined
	}

	params := &resend.SendEmailRequest{
		From:    m.from,
		To:      []string{cfg.To},
		Subject: cfg.Subject,
		Html:    html,
		Text:    cfg.Text,
		ReplyTo: cfg.ReplyTo,
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		sent, err := m.client.Emails.Send(params)
		if err == nil {
			return sent.Id, nil
		}

		if shouldRetry(err) {
			backoff := time.Duration(300*(attempt+1)) * time.Millisecond
			select {
			case <-time.After(backoff):
				lastErr = err
				continue
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		return "", fmt.Errorf("send email: %w", err)
	}
	return "", fmt.Errorf("send email after retries: %w", lastErr)
}

func renderHTML(tmpl string, data any) (string, error) {
	t, err := template.New(tmpl).Option("missingkey=zero").ParseFS(templatesFS, "templates/"+tmpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func inlineCSS(html string) (string, error) {
	p, err := premailer.NewPremailerFromString(html, &premailer.Options{
		RemoveClasses:     true,
		CssToAttributes:   true,
		KeepBangImportant: true,
	})
	if err != nil {
		return "", err
	}
	return p.Transform()
}

func shouldRetry(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "429") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "temporarily") ||
		strings.Contains(msg, "5")
}
