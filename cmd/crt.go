package cmd

import (
	"github.com/spf13/cobra"
)

// crtCmd represents the crt command (short form for --create-cert)
var crtCmd = &cobra.Command{
	Use:   "crt",
	Short: "Create certificates using an existing or newly created local certificate authority",
	Long: `Creates node and client certificates for OpenSearch Security.

This command will generate certificates for all nodes and clients defined in the configuration file.

Node certificates include Subject Alternative Names (SANs) for DNS names and IP addresses.
Client certificates are configured for client authentication.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		createCert = true // Set the flag and use common execution
		return executeAction()
	},
}

func init() {
	rootCmd.AddCommand(crtCmd)
}
