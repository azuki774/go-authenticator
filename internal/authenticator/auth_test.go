package authenticator

import (
	"fmt"
	"net/http"
	"testing"
)

func TestAuthenticator_CheckBasicAuth(t *testing.T) {
	type fields struct {
		BasicAuthMap map[string]string
		Issuer       string
		HmacSecret   string
	}
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		user   string // basic user
		pass   string // basic pass
		want   bool
	}{
		{
			name:   "no basicauth in request",
			fields: fields{},
			args:   args{r: &http.Request{}},
			want:   false,
		},
		{
			name:   "basicauth OK",
			fields: fields{},
			args:   args{r: &http.Request{Header: http.Header{}}},
			user:   "user",
			pass:   "pass",
			want:   true,
		},
		{
			name:   "basicauth NG 1",
			fields: fields{},
			args:   args{r: &http.Request{Header: http.Header{}}},
			user:   "root",
			pass:   "pass",
			want:   false,
		},
		{
			name:   "basicauth NG 2",
			fields: fields{},
			args:   args{r: &http.Request{Header: http.Header{}}},
			user:   "user",
			pass:   "passWORD",
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticator{
				BasicAuthMap: tt.fields.BasicAuthMap,
				Issuer:       tt.fields.Issuer,
				HmacSecret:   tt.fields.HmacSecret,
			}

			// test setup
			if tt.user != "" {
				tt.args.r.SetBasicAuth(tt.user, tt.pass)
			}
			a.BasicAuthMap = make(map[string]string)
			a.BasicAuthMap["user"] = "$2a$10$etIpH1oxl4Ky5koV2AzyYe42caqi/tvtme/UTwxA7lHlB2loLDOte" // SET PASSWORD - user:pass

			if got := a.CheckBasicAuth(tt.args.r); got != tt.want {
				t.Errorf("Authenticator.CheckBasicAuth() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticator_CheckCookieJWT(t *testing.T) {
	type fields struct {
		BasicAuthMap map[string]string
		Issuer       string
		HmacSecret   string
	}
	type args struct {
		r           *http.Request
		tokenString string // r に含まれるトークン
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantOk  bool
		wantErr bool
	}{
		{
			name: "ok",
			fields: fields{
				Issuer:     "testprogram",
				HmacSecret: "super_sugoi_secret",
			},
			args: args{
				r:           &http.Request{},
				tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTksImlzcyI6InRlc3Rwcm9ncmFtIn0.JQddrOcvLCTzKfPG3oCqwSe0LLcI-xcoIbrZ-DKbbJ4",
			},
			wantOk:  true,
			wantErr: false,
		},
		{
			name: "expired",
			fields: fields{
				Issuer:     "testprogram",
				HmacSecret: "super_sugoi_secret",
			},
			args: args{
				r:           &http.Request{},
				tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5LCJpc3MiOiJ0ZXN0cHJvZ3JhbSJ9.5Xx7MYFjl60ASmTChS_SROGt9Y9-4Al6ZjcWHlQGGp8",
			},
			wantOk:  false,
			wantErr: false,
		},
		{
			name: "invalid sign",
			fields: fields{
				Issuer:     "testprogram",
				HmacSecret: "super_sugoi_secret",
			},
			args: args{
				r:           &http.Request{},
				tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5LCJpc3MiOiJ0ZXN0cHJvZ3JhbSJ9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
			wantOk:  false,
			wantErr: true,
		},
		{
			name: "issuer mismatched",
			fields: fields{
				Issuer:     "testprogram",
				HmacSecret: "super_sugoi_secret",
			},
			args: args{
				r: &http.Request{},
				// this issuer is 'another_issuer'
				tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTksImlzcyI6ImFub3RoZXJfaXNzdWVyIn0.f5nLljHgEErBqaNX89fzI1vP1MHWcgbXABfZBOFzyjs",
			},
			wantOk:  false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticator{
				BasicAuthMap: tt.fields.BasicAuthMap,
				Issuer:       tt.fields.Issuer,
				HmacSecret:   tt.fields.HmacSecret,
			}
			// cookie いれる
			tt.args.r.Header = map[string][]string{
				"Cookie": {fmt.Sprintf("%s=%s", CookieJWTName, tt.args.tokenString)},
			}

			gotOk, err := a.CheckCookieJWT(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticator.CheckCookieJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotOk != tt.wantOk {
				t.Errorf("Authenticator.CheckCookieJWT() = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}
