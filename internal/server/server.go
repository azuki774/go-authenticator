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

type Server struct {
	Port int
}

func addHandler(r *chi.Mux) {
	r.Use(middleware.Logger)
	r.Get("/auth_jwt_request", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("auth_jwt_request"))
	})

	r.Get("/basic_login", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("basic_login"))
	})
}

func (s Server) Serve() error {
	// signal handler for SIGTERM, INTERRUPT
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	r := chi.NewRouter()
	addHandler(r)

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
