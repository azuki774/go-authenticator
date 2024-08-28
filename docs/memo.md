## GET /auth_jwt_request

- CookieからJWT認証を受ける
- 認証が失敗したら 400 Bad Requestを返す。
- 別途、nginx などでログイン画面に誘導する（トークンを取ってきてもらう）。

## GET /basic_login
- Basic認証を受け付け、認証があっていればJWTトークンをCookieで返す。
