package client

import (
	"fmt"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

type ClientGitHub struct {
	Conf *oauth2.Config
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

	return &ClientGitHub{Conf: conf}
}

func (c *ClientGitHub) GetLoginPageURL() string {
	url := fmt.Sprintf("%s?client_id=%s&scope=%s", c.Conf.AuthCodeURL, c.Conf.ClientID, c.Conf.Scopes[0])
	return url
}
