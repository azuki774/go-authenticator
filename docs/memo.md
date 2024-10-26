## GET /auth_jwt_request

- CookieからJWT認証を受ける
- 認証が失敗したら 401 Unauthorized を返す。
- 別途、nginx などでログイン画面に誘導する（トークンを取ってきてもらう）。

## GET /basic_login
- Basic認証を受け付け、認証があっていればJWTトークンをCookieで返す。

## GET /login_page
- github oauth2認証は繊維
    - Header: `X-Callback-URL` に値を入れると、GitHub oauth2 認証時に `redirect_uri` として値を連携する。
        - 連携成功後、このURLにコールバックされる。

## GET /callback/github?code={code}
- githubログイン後の oauth2 callback 先
