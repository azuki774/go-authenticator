package authenticator

import (
	"azuki774/go-authenticator/internal/model"
	"context"

	"go.uber.org/zap"
)

type ClientGitHub interface {
	GetAccessToken(ctx context.Context, code string) (res model.TokenResponse, err error)
}

func (a *Authenticator) HandlingGitHubOAuth(ctx context.Context, code string) (bool, error) {
	// query parameter と client_id, client_secret からaccess_tokenを取得
	accessInfo, err := a.ClientGitHub.GetAccessToken(ctx, code)
	if err != nil {
		zap.L().Error("failed to fetch access_token", zap.Error(err))
		return false, err
	}

	_ = accessInfo.AccessToken
	zap.L().Error("fetch access_token from code", zap.Error(err))

	// access_tokenからユーザーを取得

	// 登録済ユーザか判断

	return true, nil
}
