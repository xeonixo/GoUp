package web

import "embed"

//go:embed templates/*.tmpl static/*
var FS embed.FS
