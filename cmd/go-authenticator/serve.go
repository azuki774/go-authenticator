package cmd

import (
	"azuki774/go-authenticator/internal/server"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type ServeConfig struct {
	Version       int      `toml:"conf-version"`
	IssuerName    string   `toml:"isser_name"`
	Port          string   `toml:"server_port"`
	BasicAuthList []string `toml:"basicauth"`
	TokenLifeTime int      `toml:"token_lifetime"`
}

var serveConfig ServeConfig
var basicAuthMap map[string]string
var serveConfigPath string

func configLoad() (err error) {
	_, err = toml.DecodeFile(serveConfigPath, &serveConfig)
	if err != nil {
		return err
	}

	return nil
}

func basicAuthLoad() {
	basicAuthMap = make(map[string]string)
	for _, v := range serveConfig.BasicAuthList {
		userpass := strings.Split(v, ":")
		basicAuthMap[userpass[0]] = userpass[1]
	}
}

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		zap.L().Info("serve start")

		if err := configLoad(); err != nil {
			zap.L().Error("config error", zap.Error(err))
			os.Exit(1)
		}
		zap.L().Info("config loaded")

		// get secret
		secret := os.Getenv("HMAC_SECRET")
		if secret == "" {
			zap.L().Error("HMAC_SECRET is not set")
			return fmt.Errorf("HMAC_SECRET is not set")
		}

		basicAuthLoad()
		zap.L().Info("basic auth loaded")

		server := server.Server{Port: 8888}
		if err := server.Serve(); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	serveCmd.Flags().StringVarP(&serveConfigPath, "config", "c", "deployment/config.toml", "config directory")
}