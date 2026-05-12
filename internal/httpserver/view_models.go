package httpserver

type paginationView struct {
	Page      int
	PageCount int
	Total     int64
	HasPrev   bool
	HasNext   bool
	PrevPage  int
	NextPage  int
	BaseURL   string
}

type languageOptionView struct {
	Code     string
	Label    string
	Selected bool
}

type adminProviderOverviewRow struct {
	TenantID    int64
	TenantName  string
	TenantSlug  string
	ProviderKey string
	Kind        string
	DisplayName string
	Enabled     bool
}

type adminUserOverviewRow struct {
	TenantID            int64
	TenantName          string
	TenantSlug          string
	UserID              int64
	LoginName           string
	Email               string
	DisplayName         string
	Role                string
	LastLoginAt         string
	LastLoginAtRaw      string
	HasLocalCredentials bool
	HasOIDCIdentity     bool
}

type adminRemoteNodeOverviewRow struct {
	TenantID        int64
	TenantName      string
	TenantSlug      string
	NodeID          string
	Name            string
	Online          bool
	LastSeenAt      string
	LastSeenAtRaw   string
	HeartbeatWindow string
}
