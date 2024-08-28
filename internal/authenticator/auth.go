package authenticator

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"azuki774/go-authenticator/internal/util"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const CookieJWTName = "jwt"

type Authenticator struct {
	BasicAuthMap map[string]string
	Issuer       string
	HmacSecret   string
}

func (a *Authenticator) CheckBasicAuth(r *http.Request) bool {
	// 認証情報取得
	reqUser, reqPass, ok := r.BasicAuth()
	if !ok {
		zap.L().Warn("not set basicauth", zap.String("user", reqUser))
		return false
	}
	hashPass, ok := a.BasicAuthMap[reqUser] // 正しいパスワードのハッシュを取得
	if !ok {
		zap.L().Warn("this user is not found", zap.String("user", reqUser))
		return false
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashPass), []byte(reqPass)); err != nil {
		zap.L().Warn("basic auth mismatched", zap.String("user", reqUser))
		return false
	}

	return true
}

func (a *Authenticator) CheckCookieJWT(r *http.Request) (ok bool, err error) {
	tokenCookie, err := r.Cookie(CookieJWTName)
	if err != nil {
		// unknown error: http: named cookie not present
		// token の key がない場合もここに落ちるので、この場合は ok = false とする
		return false, nil
	}

	tokenString := tokenCookie.Value
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(a.HmacSecret), nil
	})
	if err != nil {
		// token expired も含む
		if errors.Is(err, jwt.ErrTokenExpired) {
			zap.L().Warn("token expired", zap.String("jwt", maskedJwt(tokenString)))
			return false, nil
		}
		return false, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if claims["iss"] != a.Issuer {
			zap.L().Warn("issuer mismatched", zap.String("jwt", maskedJwt(tokenString)))
			return false, nil
		}
	} else {
		return false, err
	}

	return true, nil
}

func (a *Authenticator) GenerateCookie(life int) (*http.Cookie, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": util.NowFunc().Unix() + int64(life),
		"iss": a.Issuer,
	})
	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(a.HmacSecret))
	if err != nil {
		zap.L().Error("failed to generate JWT access token", zap.Error(err))
		return nil, fmt.Errorf("failed to generate JWT access token: %w", err)
	}
	cookie := &http.Cookie{
		Name:   CookieJWTName,
		Value:  tokenString,
		MaxAge: int(life), // life 秒後まで Cookie を保つ
	}

	return cookie, nil
}

func maskedJwt(tokenString string) string {
	splitsToken := strings.Fields(tokenString) // 'AAA.BBB.CCC' -> ['AAA','BBB','CCC']
	if len(splitsToken) != 3 {
		return tokenString
	}
	splitsToken[2] = "***"
	return fmt.Sprintf("%s.%s.%s", splitsToken[0], splitsToken[1], splitsToken[2])
}
