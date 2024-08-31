package authenticator

import (
	"azuki774/go-authenticator/internal/model"
	"context"

	"go.uber.org/zap"
)

type ClientGitHub interface {
	GetAccessToken(ctx context.Context, code string) (res model.TokenResponse, err error)
	GetUser(ctx context.Context, accessToken string) (user model.GitHubUser, err error)
}

func (a *Authenticator) HandlingGitHubOAuth(ctx context.Context, code string) (bool, error) {
	// query parameter と client_id, client_secret からaccess_tokenを取得
	accessInfo, err := a.ClientGitHub.GetAccessToken(ctx, code)
	if err != nil {
		zap.L().Error("failed to fetch access_token", zap.Error(err))
		return false, err
	}

	accessToken := accessInfo.AccessToken
	zap.L().Error("fetch access_token from code", zap.Error(err))

	// access_tokenからユーザーを取得
	user, err := a.ClientGitHub.GetUser(ctx, accessToken)
	if err != nil {
		zap.L().Error("failed to get userid", zap.Error(err))
		return false, err
	}
	id := user.ID // user API のレスポンスから ID を抽出

	// 登録済ユーザか判断
	if !a.AllowGitHubList[id] {
		zap.L().Error("this user is not allowed from config", zap.Int("id", id))
		return false, nil
	}

	zap.L().Info("this user is authorized", zap.Int("id", id))
	return true, nil
}
