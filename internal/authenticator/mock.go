package authenticator

import (
	"azuki774/go-authenticator/internal/model"
	"context"
)

type mockClientGitHub struct {
	err error
}

func (m *mockClientGitHub) GetAccessToken(ctx context.Context, code string) (res model.TokenResponse, err error) {
	if m.err != nil {
		return model.TokenResponse{}, m.err
	}

	res = model.TokenResponse{
		AccessToken:           "access_token_abcdefghijklmnopqrstuvwxyz",
		ExpiresIn:             28800,
		RefreshToken:          "refresh_token_abcdefghijklmnopqrstuvwxyz",
		RefreshTokenExpiresIn: 15724800,
		TokenType:             "bearer",
		Scope:                 "",
	}

	return res, nil
}

func (m *mockClientGitHub) GetUser(ctx context.Context, accessCode string) (user model.GitHubUser, err error) {
	if m.err != nil {
		return model.GitHubUser{}, m.err
	}
	return model.GitHubUser{ID: 100000}, nil
}
