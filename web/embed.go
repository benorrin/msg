// Package web embeds the browser client so the server ships as one binary.
package web

import "embed"

//go:embed index.html style.css js
var FS embed.FS
