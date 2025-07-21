package cmd

import (
	"github.com/spf13/cobra"
)

// csrCmd represents the csr command (short form for --create-csr)
var csrCmd = &cobra.Command{
	Use:   "csr",
	Short: "Create certificate signing requests",
	Long: `Creates certificate signing requests (CSRs) for external signing.

This functionality is not yet implemented but will generate CSR files
that can be sent to an external Certificate Authority for signing.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		createCSR = true // Set the flag and use common execution
		return executeAction()
	},
}

func init() {
	rootCmd.AddCommand(csrCmd)
}
