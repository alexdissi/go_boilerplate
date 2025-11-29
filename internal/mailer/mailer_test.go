package mailer

import (
	"context"
	"testing"

	"go.uber.org/mock/gomock"
)

func TestSendWelcomeEmail_CallsMailer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mock := NewMockMailer(ctrl)

	email := "user@example.com"
	first := "John"
	last := "Doe"
	token := "abc123"

	mock.
		EXPECT().
		SendMail(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, cfg Config) (string, error) {
			if cfg.To != email {
				t.Errorf("To mismatch: got %s", cfg.To)
			}
			if cfg.Subject == "" || cfg.TemplateName != "welcome.html.tmpl" {
				t.Errorf("unexpected subject/template: %q / %q", cfg.Subject, cfg.TemplateName)
			}
			return "email-id-123", nil
		}).
		Times(1)

	if err := SendWelcomeEmail(context.Background(), mock, email, first, last, token); err != nil {
		t.Fatalf("SendWelcomeEmail error: %v", err)
	}
}

func TestSendResetPasswordEmail_CallsMailer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mock := NewMockMailer(ctrl)

	email := "user@example.com"
	first := "John"
	reset := "https://example.com/reset?token=abc"

	mock.
		EXPECT().
		SendMail(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, cfg Config) (string, error) {
			if cfg.To != email {
				t.Errorf("To mismatch: got %s", cfg.To)
			}
			if cfg.Subject == "" || cfg.TemplateName != "reset-password.html.tmpl" {
				t.Errorf("unexpected subject/template: %q / %q", cfg.Subject, cfg.TemplateName)
			}
			return "email-id-456", nil
		}).
		Times(1)

	if err := SendResetPasswordEmail(context.Background(), mock, email, first, reset); err != nil {
		t.Fatalf("SendResetPasswordEmail error: %v", err)
	}
}

func TestSendSubscriptionConfirmationEmail_CallsMailer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mock := NewMockMailer(ctrl)

	email := "user@example.com"
	first := "Jane"
	plan := "Pro"

	mock.
		EXPECT().
		SendMail(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, cfg Config) (string, error) {
			if cfg.To != email {
				t.Errorf("To mismatch: got %s", cfg.To)
			}
			// Nouveau: on vérifie le template "subscription.html.tmpl"
			if cfg.Subject == "" || cfg.TemplateName != "subscription.html.tmpl" {
				t.Errorf("unexpected subject/template: %q / %q", cfg.Subject, cfg.TemplateName)
			}
			return "email-id-789", nil
		}).
		Times(1)

	if err := SendSubscriptionConfirmationEmail(context.Background(), mock, email, first, plan); err != nil {
		t.Fatalf("SendSubscriptionConfirmationEmail error: %v", err)
	}
}
