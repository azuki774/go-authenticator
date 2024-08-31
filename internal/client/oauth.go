package client

import (
	"azuki774/go-authenticator/internal/model"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

type ClientGitHub struct {
	AuthConf *oauth2.Config
}

func NewClientGitHubConf() *ClientGitHub {
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
