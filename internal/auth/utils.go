package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

var (
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	hasLowerRegex = regexp.MustCompile(`[a-z]`)
	hasUpperRegex = regexp.MustCompile(`[A-Z]`)
	hasDigitRegex = regexp.MustCompile(`\d`)
	hasSpecRegex  = regexp.MustCompile(`[@$!%*?&]`)
)

func GenerateAvatarURL(firstName, lastName *string) string {
	var initials string

	switch {
	case firstName != nil && *firstName != "" && lastName != nil && *lastName != "":
		initials = strings.ToUpper(string((*firstName)[0])) + strings.ToUpper(string((*lastName)[0]))
	case firstName != nil && len(*firstName) >= 2:
		initials = strings.ToUpper((*firstName)[:2])
	case lastName != nil && len(*lastName) >= 2:
		initials = strings.ToUpper((*lastName)[:2])
	default:
		return "https://api.dicebear.com/9.x/initials/svg?seed="
	}

	return fmt.Sprintf("https://api.dicebear.com/9.x/initials/svg?seed=%s", initials)
}

func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func GenerateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func IsValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}

func IsStrongPassword(password string) bool {
	if len(password) < 8 || len(password) > 72 {
		return false
	}
	return hasLowerRegex.MatchString(password) &&
		hasUpperRegex.MatchString(password) &&
		hasDigitRegex.MatchString(password) &&
		hasSpecRegex.MatchString(password)
}
