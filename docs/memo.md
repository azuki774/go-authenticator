## GET /auth_jwt_request

- CookieからJWT認証を受ける
- 認証が失敗したら 401 Unauthorized を返す。
- 別途、nginx などでログイン画面に誘導する（トークンを取ってきてもらう）。

## GET /basic_login
- Basic認証を受け付け、認証があっていればJWTトークンをCookieで返す。

## GET /login_page
- ログイン方法を選択

## GET /callback/github?code={code}
- githubログイン後の oauth2 callback 先
