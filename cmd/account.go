package cmd

import (
	"encoding/json"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/models"
	"github.com/spf13/cobra"
)

var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Get current WARP account information and traffic quota",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		accountData := models.AccountData{
			ID:    config.AppConfig.ID,
			Token: config.AppConfig.AccessToken,
		}

		updatedAccount, err := api.GetAccount(accountData)
		if err != nil {
			cmd.Printf("Failed to get account info: %v\n", err)
			return
		}

		prettyJson, _ := json.MarshalIndent(updatedAccount, "", "  ")
		cmd.Println(string(prettyJson))
	},
}

func init() {
	rootCmd.AddCommand(accountCmd)
}
