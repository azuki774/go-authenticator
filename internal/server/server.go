package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

type Server struct {
	Port          int
	Authenticator Authenticator
	CookieLife    int    // token_life, cookie: max-age
	BasePath      string // BasePath for redirect_url
}

type Authenticator interface {
	CheckBasicAuth(r *http.Request) bool
	CheckCookieJWT(r *http.Request) (ok bool, err error)
	GenerateCookie(life int) (*http.Cookie, error)
	// GitHub OAuth2 で access_token 引き換え code 入力から、JWT発行してよいかどうかを判断するところまで
	HandlingGitHubOAuth(ctx context.Context, code string) (ok bool, err error)
}

// https://hoge.example.com/callback/github -> https://hoge.example.com/
func (s Server) getServerBaseURL(r *url.URL) string {
	return r.Scheme + "://" + r.Host + s.BasePath
}

func (s Server) addHandler(r *chi.Mux) {
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

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

	r.Get("/login_page", func(w http.ResponseWriter, r *http.Request) {
		clientId := os.Getenv("GITHUB_CLIENT_ID") // TODO
		url := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&scope=user:read", clientId)
		zap.L().Info(fmt.Sprintf("move to %s", url))
		http.Redirect(w, r, url, http.StatusFound)
	})

	r.Get("/callback/github", func(w http.ResponseWriter, r *http.Request) {
		zap.L().Info("callback received")

		queryParams := r.URL.Query()
		code := queryParams.Get("code")
		if code == "" {
			zap.L().Warn("code is empty")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		ok, err := s.Authenticator.HandlingGitHubOAuth(r.Context(), code)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !ok {
			zap.L().Warn("this user is not authorized")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// ここまで問題なければ JWT トークンを発行
		cookie, err := s.Authenticator.GenerateCookie(s.CookieLife)
		if err != nil {
			return
		}

		http.SetCookie(w, cookie)
		zap.L().Info("set Cookie")

		// エラーでなければ親ページに返してあげる
		zap.L().Info(fmt.Sprintf("move to %s", s.getServerBaseURL(r.URL)))
		http.Redirect(w, r, s.getServerBaseURL(r.URL), http.StatusFound)

		zap.L().Info("callback process done")
	})
}

func (s Server) Serve() error {
	// signal handler for SIGTERM, INTERRUPT
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	r := chi.NewRouter()
	r.Use(s.publishAuthReqID)
	r.Use(s.middlewareLogging)
	s.addHandler(r)

	srv := http.Server{
		Addr:    fmt.Sprintf(":%d", s.Port),
		Handler: r,
	}

	zap.L().Info("start server", zap.Int("port", s.Port))
	go srv.ListenAndServe()

	<-ctx.Done()
	zap.L().Info("shutdown signal detected")
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
