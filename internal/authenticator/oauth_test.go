package authenticator

import (
	"context"
	"errors"
	"testing"
)

func TestAuthenticator_HandlingGitHubOAuth(t *testing.T) {
	type fields struct {
		BasicAuthMap    map[string]string
		Issuer          string
		HmacSecret      string
		AllowGitHubList map[int]bool
		ClientGitHub    ClientGitHub
	}
	type args struct {
		ctx  context.Context
		code string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "ok",
			fields: fields{
				AllowGitHubList: map[int]bool{100000: true},
				ClientGitHub:    &mockClientGitHub{},
			},
			args: args{
				ctx:  context.Background(),
				code: "0123456789abcdef",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "unknown user",
			fields: fields{
				AllowGitHubList: map[int]bool{100001: true},
				ClientGitHub:    &mockClientGitHub{},
			},
			args: args{
				ctx:  context.Background(),
				code: "0123456789abcdef",
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "github error",
			fields: fields{
				AllowGitHubList: map[int]bool{100000: true},
				ClientGitHub:    &mockClientGitHub{err: errors.New("something error")},
			},
			args: args{
				ctx:  context.Background(),
				code: "0123456789abcdef",
			},
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticator{
				BasicAuthMap:    tt.fields.BasicAuthMap,
				Issuer:          tt.fields.Issuer,
				HmacSecret:      tt.fields.HmacSecret,
				AllowGitHubList: tt.fields.AllowGitHubList,
				ClientGitHub:    tt.fields.ClientGitHub,
			}
			got, err := a.HandlingGitHubOAuth(tt.args.ctx, tt.args.code)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticator.HandlingGitHubOAuth() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Authenticator.HandlingGitHubOAuth() = %v, want %v", got, tt.want)
			}
		})
	}
}
