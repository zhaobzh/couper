package server

import (
	"net/http"
	"strings"

	ac "go.avenga.cloud/couper/gateway/access_control"
	"go.avenga.cloud/couper/gateway/config"
	"go.avenga.cloud/couper/gateway/errors"
	"go.avenga.cloud/couper/gateway/handler"
)

// Muxer object
type Muxer struct {
	mux *config.Mux
}

// NewMuxer creates a new Muxer object
func NewMuxer(mux *config.Mux) *Muxer {
	return &Muxer{mux: mux}
}

// Match tries to find a http.Handler by the given request
func (m *Muxer) Match(req *http.Request) http.Handler {
	if len(m.mux.API) > 0 {
		if h, ok := NewRouter(m.mux.API).Match(req); ok {
			return h
		}

		if m.isAPIError(req.URL.Path) {
			return m.mux.APIErrTpl.ServeError(errors.APIRouteNotFound)
		}
	}

	if len(m.mux.FS) > 0 {
		if h, ok := NewRouter(m.mux.FS).Match(req); ok {
			fileHandler := h
			if p, isProtected := h.(ac.ProtectedHandler); isProtected {
				fileHandler = p.Child()
			}
			if fh, ok := fileHandler.(handler.HasResponse); ok && fh.HasResponse(req) {
				return h
			}
		}
	}

	if len(m.mux.SPA) > 0 {
		if h, ok := NewRouter(m.mux.SPA).Match(req); ok {
			return h
		}
	}

	if len(m.mux.FS) > 0 && m.isFileError(req.URL.Path) {
		return m.mux.FSErrTpl.ServeError(errors.FilesRouteNotFound)
	}

	return nil
}

func (m *Muxer) isAPIError(reqPath string) bool {
	p1 := m.mux.APIPath
	p2 := m.mux.APIPath

	if p2 != "/" {
		p2 = p2[:len(p2)-len("/")]
	}

	if strings.HasPrefix(reqPath, p1) || reqPath == p2 {
		if len(m.mux.FS) > 0 && m.mux.APIPath == m.mux.FSPath {
			return false
		}
		if len(m.mux.SPA) > 0 && m.mux.APIPath == m.mux.SPAPath {
			return false
		}

		return true
	}

	return false
}

func (m *Muxer) isFileError(reqPath string) bool {
	p1 := m.mux.FSPath
	p2 := m.mux.FSPath

	if p2 != "/" {
		p2 = p2[:len(p2)-len("/")]
	}

	if strings.HasPrefix(reqPath, p1) || reqPath == p2 {
		return true
	}

	return false
}
