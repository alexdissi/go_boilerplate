package mailer

type WelcomeData struct {
	FirstName   string
	LastName    string
	ProductName string
	ActionURL   string
	Year        int
}

type ResetData struct {
	Name      string
	ResetLink string
	Year      int
}

type SubscriptionData struct {
	Name         string
	Plan         string
	DashboardURL string
	Year         int
}
