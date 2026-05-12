package httpserver

import (
	"regexp"
)

type dashboardIconAsset struct {
	Payload     []byte
	ContentType string
}

type dashboardIconMetadata struct {
	Aliases    []string `json:"aliases"`
	Categories []string `json:"categories"`
}

type dashboardIconEntry struct {
	Slug       string
	Label      string
	SearchText string
	Value      string
	Source     string
	Preferred  bool
}

type dashboardIconSearchResult struct {
	Value     string `json:"value"`
	Slug      string `json:"slug"`
	Label     string `json:"label"`
	URL       string `json:"url"`
	Source    string `json:"source"`
	Preferred bool   `json:"preferred"`
}

const (
	dashboardIconsBaseURL     = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons"
	dashboardIconsMetadataURL = "https://raw.githubusercontent.com/homarr-labs/dashboard-icons/refs/heads/main/metadata.json"
	dashboardIconSearchLimit  = 24
	groupIconUploadPrefix     = "upload:"
	groupIconUploadMaxBytes   = 2 << 20
)

var (
	tenantIconDirKeyPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	dashboardIconFileSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)
