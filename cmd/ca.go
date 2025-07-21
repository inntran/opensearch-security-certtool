package cmd

import (
	"github.com/spf13/cobra"
)

// caCmd represents the ca command (short form for --create-ca)
var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Create a new certificate authority",
	Long: `Creates a new Certificate Authority (CA) certificate and private key.
This can include both root CA and intermediate CA if configured.

The CA certificates and keys will be saved to the target directory.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		createCA = true // Set the flag and use common execution
		return executeAction()
	},
}

func init() {
	rootCmd.AddCommand(caCmd)
}
