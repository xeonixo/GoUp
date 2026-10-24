package httpserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"goup/web"
)

const (
	// stylesheetURLPath is the request path (relative to /static/) that serves
	// the concatenation of the ordered CSS sources under static/css/.
	stylesheetURLPath = "style.css"
	stylesheetSrcDir  = "static/css"
)

var (
	stylesheetOnce  sync.Once
	stylesheetBytes []byte
)

// stylesheetBundle returns the site stylesheet: every static/css/*.css source
// file concatenated in name order, which preserves the original cascade. It is
// built once per process.
func stylesheetBundle() []byte {
	stylesheetOnce.Do(func() {
		stylesheetBytes = buildStylesheet(web.FS, stylesheetSrcDir)
	})
	return stylesheetBytes
}

// buildStylesheet concatenates the *.css files of dir in lexical name order.
func buildStylesheet(fsys fs.FS, dir string) []byte {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".css") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var buf bytes.Buffer
	for i, name := range names {
		data, err := fs.ReadFile(fsys, path.Join(dir, name))
		if err != nil {
			continue
		}
		if i > 0 {
			buf.WriteByte('\n')
		}
		buf.Write(data)
	}
	return buf.Bytes()
}

// staticETags caches the strong ETag of each served static path.
type staticETags struct {
	fsys fs.FS
	tags sync.Map // clean path -> quoted ETag
}

// etag returns the strong ETag (content hash) for name, computed once.
func (c *staticETags) etag(name string, read func() ([]byte, error)) (string, bool) {
	if v, ok := c.tags.Load(name); ok {
		return v.(string), true
	}
	data, err := read()
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(data)
	tag := `"` + hex.EncodeToString(sum[:12]) + `"`
	c.tags.Store(name, tag)
	return tag, true
}

// serveStylesheet serves the bundled stylesheet; ServeContent honours
// If-None-Match using the ETag set on the response.
func (c *staticETags) serveStylesheet(w http.ResponseWriter, r *http.Request) {
	body := stylesheetBundle()
	if tag, ok := c.etag(stylesheetURLPath, func() ([]byte, error) { return body, nil }); ok {
		w.Header().Set("ETag", tag)
	}
	http.ServeContent(w, r, stylesheetURLPath, time.Time{}, bytes.NewReader(body))
}

// setETag adds the ETag header for an existing regular file in fsys so the
// file server answers conditional requests with 304.
func (c *staticETags) setETag(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		return
	}
	tag, ok := c.etag(name, func() ([]byte, error) { return fs.ReadFile(c.fsys, name) })
	if ok {
		w.Header().Set("ETag", tag)
	}
}
