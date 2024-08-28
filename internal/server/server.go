package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"go.uber.org/zap"
	"golang.org/x/exp/slog"
)

func init() {
	// Logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	zap.ReplaceGlobals(logger)
}

type Server struct {
	Port          int
	Authenticator Authenticator
	CookieLife    int // token_life, cookie: max-age
}

type Authenticator interface {
	CheckBasicAuth(r *http.Request) bool
	CheckCookieJWT(r *http.Request) (ok bool, err error)
	GenerateCookie(life int) (*http.Cookie, error)
}

func (s Server) addHandler(r *chi.Mux) {
	r.Use(middleware.Logger)
	r.Get("/auth_jwt_request", func(w http.ResponseWriter, r *http.Request) {
		ok, err := s.Authenticator.CheckCookieJWT(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// auth ok
	})

	r.Get("/basic_login", func(w http.ResponseWriter, r *http.Request) {
		ok := s.Authenticator.CheckBasicAuth(r)
		if !ok {
			w.Header().Add("WWW-Authenticate", `Basic realm="SECRET AREA"`)
			w.WriteHeader(http.StatusUnauthorized) // 401
			return
		}

		// new cookie
		// Generate Cookie
		cookie, err := s.Authenticator.GenerateCookie(s.CookieLife)
		if err != nil {
			return
		}

		http.SetCookie(w, cookie)
		zap.L().Info("set Cookie")
	})
}

func (s Server) Serve() error {
	// signal handler for SIGTERM, INTERRUPT
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	r := chi.NewRouter()
	s.addHandler(r)

	srv := http.Server{
		Addr:    fmt.Sprintf(":%d", s.Port),
		Handler: r,
	}

	zap.L().Info("start server", zap.Int("port", s.Port))
	go srv.ListenAndServe()

	<-ctx.Done()
	slog.Info("shutdown signal detected")
	// 5sec timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := srv.Shutdown(ctx)
	if err != nil {
		zap.L().Error("server shutdown error", zap.Error(err))
		return err
	}

	zap.L().Info("shutdown server gracefully")
	return nil
}
