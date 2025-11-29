package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

func GenerateAvatarURL(firstName, lastName *string) string {
	initials := ""
	if firstName != nil && lastName != nil {
		initials = fmt.Sprintf("%s%s", strings.ToUpper((*firstName)[:1]), strings.ToUpper((*lastName)[:1]))
	} else if firstName != nil {
		initials = strings.ToUpper((*firstName)[:1]) + (*firstName)[1:2]
	} else if lastName != nil {
		initials = strings.ToUpper((*lastName)[:1]) + (*lastName)[1:2]
	} else {
		return "https://api.dicebear.com/9.x/initials/svg?seed="
	}

	return fmt.Sprintf("https://api.dicebear.com/9.x/initials/svg?seed=%s", initials)
}

func GenerateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func IsValidEmail(email string) bool {
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegex)

	return re.MatchString(email)
}

func IsStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`\d`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[@$!%*?&]`).MatchString(password)

	return hasLower && hasUpper && hasDigit && hasSpecial
}
