package httpserver

// systemPageView is the read-only data behind /admin/system. Every value is pre-formatted so the
// template stays free of logic; Err fields carry per-section failures instead of failing the page.
type systemPageView struct {
	GeneratedAt string
	Process     systemProcessView
	Storage     systemStorageView
	Tenants     []systemTenantView
	Failures    []systemFailureView
	RemoteNodes systemRemoteNodesView
}

type systemProcessView struct {
	Version       string
	GoVersion     string
	Uptime        string
	Goroutines    int
	HeapInUse     string
	Sys           string
	GOMAXPROCS    int
	TenantCount   int
	ActiveRunners int
}

type systemStorageView struct {
	DataDir   string
	FreeSpace string
	FreeKnown bool
	Files     []systemDBFileView
}

// systemDBFileView describes one SQLite database (main file plus -wal and -shm).
type systemDBFileView struct {
	Label        string
	RelPath      string
	Missing      bool
	Size         string
	WAL          string
	SHM          string
	TotalBytes   int64
	WALBytes     int64
	LargeDB      bool
	LargeWAL     bool
	RetentionRaw string
	RollupRaw    string
}

type systemTenantView struct {
	Name           string
	Slug           string
	Active         bool
	HasRunner      bool
	Err            string
	EnabledMonitor int
	Workers        int
	ChecksLast5Min int
	Running        int
	Backlog        int
	LastLoop       string
	AvgCheck       string
	RetryQueue     int
	OldestRetryRaw string
	Delivered24h   int
	Failed24h      int
	Suppressed24h  int
}

type systemFailureView struct {
	TimeRaw  string
	Tenant   string
	Monitor  string
	Endpoint string
	Event    string
	Error    string
}

// systemRemoteNodesView is the remote node summary card; further counters can be added here.
type systemRemoteNodesView struct {
	Total   int
	Online  int
	Offline int
	// Outdated counts nodes whose agent is older than the server.
	Outdated int
	Err      string
}
