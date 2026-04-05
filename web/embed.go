package web

import "embed"

//go:embed templates/*.tmpl static/* i18n/*.json
var FS embed.FS
