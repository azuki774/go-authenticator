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
	"golang.org/x/exp/slog"
)

type Server struct {
	Port int
}

func (s Server) Serve() error {
	// signal handler for SIGTERM, INTERRUPT
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})

	srv := http.Server{
		Addr:    fmt.Sprintf(":%d", s.Port),
		Handler: r,
	}

	slog.Info("start server", slog.Int("port", s.Port))
	go srv.ListenAndServe()

	<-ctx.Done()
	slog.Info("shutdown signal detected")
	// 5sec timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := srv.Shutdown(ctx)
	if err != nil {
		slog.Error("server shutdown error", slog.String("err", err.Error()))
		return err
	}

	slog.Info("shutdown server gracefully")
	return nil
}
