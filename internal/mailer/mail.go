package mailer

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

func SendWelcomeEmail(ctx context.Context, client Mailer, email, firstName, lastName, token string) error {
	data := WelcomeData{
		FirstName:   firstName,
		LastName:    lastName,
		ProductName: "Figenn",
		ActionURL:   os.Getenv("APP_URL") + "/activate?token=" + token,
		Year:        time.Now().Year(),
	}
	_, err := client.SendMail(ctx, Config{
		To:           email,
		Subject:      "Welcome to Figenn 🚀",
		TemplateName: "welcome.html.tmpl",
		Data:         data,
		Text:         fmt.Sprintf("Welcome %s %s! Activate your account: %s", data.FirstName, data.LastName, data.ActionURL),
	})
	return err
}

func SendResetPasswordEmail(ctx context.Context, client Mailer, email, name, resetLink string) error {
	data := ResetData{
		Name:      name,
		ResetLink: resetLink,
		Year:      time.Now().Year(),
	}
	_, err := client.SendMail(ctx, Config{
		To:           email,
		Subject:      "Reset your Figenn password",
		TemplateName: "reset-password.html.tmpl",
		Data:         data,
		Text:         fmt.Sprintf("Hello %s, reset your password here (expires in 1 hour): %s", data.Name, data.ResetLink),
	})
	return err
}

func SendSubscriptionConfirmationEmail(ctx context.Context, client Mailer, email, name, plan string) error {
	dashboard := strings.TrimRight(os.Getenv("APP_URL"), "/") + "/dashboard"
	data := SubscriptionData{
		Name:         name,
		Plan:         plan,
		DashboardURL: dashboard,
		Year:         time.Now().Year(),
	}
	_, err := client.SendMail(ctx, Config{
		To:           email,
		Subject:      "Your Figenn subscription is active",
		TemplateName: "subscription.html.tmpl",
		Data:         data,
		Text:         fmt.Sprintf("Hi %s, your %s subscription is active. Dashboard: %s", data.Name, data.Plan, data.DashboardURL),
	})
	return err
}
