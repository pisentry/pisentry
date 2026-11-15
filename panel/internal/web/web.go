// Package web serves the built web UI from the binary. `make ui` builds it
// from panel/web into dist; without that, a short placeholder page is served
// and the API still works.
package web

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

const placeholder = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>pisentry panel</title></head>
<body><h1>pisentry panel</h1><p>This binary was built without the web UI. Run <code>make ui build</code> in <code>panel/</code>. The API is up at <code>/api/</code>.</p></body></html>
`

// Built reports whether the UI was built into this binary.
func Built() bool {
	_, err := fs.Stat(dist, "dist/index.html")
	return err == nil
}

// Handler serves the UI. Paths that aren't files get index.html so the
// app's own routes work on reload.
func Handler() http.Handler {
	if !Built() {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, placeholder)
		})
	}
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" || p == "." {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err != nil || strings.HasPrefix(path.Base(p), ".") {
			if strings.HasPrefix(p, "api/") || strings.HasPrefix(p, "assets/") {
				http.NotFound(w, r)
				return
			}
			r = r.Clone(r.Context())
			r.URL.Path = "/"
			p = "index.html"
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}
