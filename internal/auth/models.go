package auth

var (
	GoogleProvider = "google"
)

type RegisterRequest struct {
	Email     string `json:"email" validate:"required,email" form:"email"`
	Password  string `json:"password" validate:"required,min=8,max=32" form:"password"`
	FirstName string `json:"firstName" validate:"required,min=2,max=50" form:"firstName"`
	LastName  string `json:"lastName" validate:"required,min=2,max=50" form:"lastName"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email" form:"email"`
	Password string `json:"password" validate:"required" form:"password"`
}

type ActivateAccountRequest struct {
	Token string `json:"token" validate:"required" form:"token"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email" form:"email"`
}

type ResetPasswordRequest struct {
	Token    string `json:"token" validate:"required" form:"token"`
	Password string `json:"password" validate:"required,min=8,max=32" form:"password"`
}

type TOTPSetupRequest struct {
	Password string `json:"password" validate:"required" form:"password"`
}

type TOTPSetupResponse struct {
	Secret      string   `json:"secret"`
	QRCode      string   `json:"qrCode"`
	BackupCodes []string `json:"backupCodes"`
}

type TOTPVerifyRequest struct {
	Token      string `json:"token" validate:"required,len=6" form:"token"`
	RememberMe bool   `json:"rememberMe" form:"rememberMe"`
}

type TOTPEnableRequest struct {
	Token string `json:"token" validate:"required,len=6" form:"token"`
}

type TOTPDisableRequest struct {
	Token    string `json:"token" validate:"required,len=6" form:"token"`
	Password string `json:"password" validate:"required" form:"password"`
}

type LoginWithTOTPRequest struct {
	Email      string `json:"email" validate:"required,email" form:"email"`
	Password   string `json:"password" validate:"required" form:"password"`
	TOTPToken  string `json:"totpToken" validate:"required,len=6" form:"totpToken"`
	RememberMe bool   `json:"rememberMe" form:"rememberMe"`
}

type GoogleAuthURLResponse struct {
	URL string `json:"url"`
}

type GoogleUserInfo struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
	Given   string `json:"given_name"`
	Family  string `json:"family_name"`
	Locale  string `json:"locale"`
}
