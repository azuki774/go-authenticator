package client

import (
	"azuki774/go-authenticator/internal/model"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

const githubAPIUserEndpoint = "https://api.github.com/user"

type ClientGitHub struct {
	AuthConf *oauth2.Config
}

func NewClientGitHub() *ClientGitHub {
	conf := &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		Scopes:       []string{"user:read"}, // scope は1つだけ対応
		Endpoint: oauth2.Endpoint{
			TokenURL: endpoints.GitHub.TokenURL,
			AuthURL:  endpoints.GitHub.AuthURL,
		},
	}

	return &ClientGitHub{AuthConf: conf}
}

func (c *ClientGitHub) GetAccessToken(ctx context.Context, code string) (res model.TokenResponse, err error) {
	reqData := model.TokenRequest{
		ClientID:     c.AuthConf.ClientID,
		ClientSecret: c.AuthConf.ClientSecret,
		Code:         code,
	}

	reqDataBin, err := json.Marshal(&reqData)
	if err != nil {
		return model.TokenResponse{}, err
	}

	req, err := http.NewRequest(
		"POST",
		c.AuthConf.Endpoint.TokenURL,
		bytes.NewBuffer(reqDataBin),
	)
	if err != nil {
		return model.TokenResponse{}, err
	}

	// Content-Type 設定
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return model.TokenResponse{}, err
	}
	defer resp.Body.Close()

	respBin, err := io.ReadAll(resp.Body)
	if err != nil {
		return model.TokenResponse{}, err
	}

	err = json.Unmarshal(respBin, &res)
	if err != nil {
		return model.TokenResponse{}, err
	}

	return res, nil
}

func (c *ClientGitHub) GetUser(ctx context.Context, accessToken string) (user model.GitHubUser, err error) {
	req, err := http.NewRequest(
		"GET",
		githubAPIUserEndpoint,
		nil,
	)

	// Content-Type 設定
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return model.GitHubUser{}, err
	}
	defer resp.Body.Close()

	respBin, err := io.ReadAll(resp.Body)
	if err != nil {
		return model.GitHubUser{}, err
	}

	err = json.Unmarshal(respBin, &user)
	if err != nil {
		return model.GitHubUser{}, err
	}
	return user, nil
}
