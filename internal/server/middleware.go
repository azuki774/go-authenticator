package server

import (
	"azuki774/go-authenticator/internal/util"
	"context"
	"net/http"

	"go.uber.org/zap"
)

type contextKey string

var authReqIdKey = contextKey("authRequestId")

func (s *Server) middlewareLogging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Context().Value(authReqIdKey)
		authReqId, _ := v.(string)
		zap.L().Info("access",
			zap.String("url", r.URL.Path),
			zap.String("User-Agent", r.UserAgent()),
			zap.String("Remote-Addr", r.RemoteAddr),
			zap.String("authRequestId", authReqId),
		)
		h.ServeHTTP(w, r)
	})
}

func (s *Server) publishAuthReqID(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := util.PublishID()
		ctxWithID := context.WithValue(r.Context(), authReqIdKey, id)
		h.ServeHTTP(w, r.WithContext(ctxWithID))
	})
}
