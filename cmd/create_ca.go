package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/inntran/opensearch-security-certtool/internal/cert"
	"github.com/inntran/opensearch-security-certtool/internal/config"
)

// createCACmd represents the create-ca command
var createCACmd = &cobra.Command{
	Use:   "create-ca",
	Short: "Create a new certificate authority",
	Long: `Creates a new Certificate Authority (CA) certificate and private key.
This can include both root CA and intermediate CA if configured.

The CA certificates and keys will be saved to the target directory.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return createCACommand()
	},
}

// createCACommand implements the CA creation logic
func createCACommand() error {
		fmt.Println("Creating Certificate Authority...")
		
		// Create output directory if it doesn't exist
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
		
		var rootCA *cert.CAInfo
		var err error
		
		// Create root CA
		if cfg.CA.Root.DN != "" {
			if verbose {
				fmt.Printf("Creating root CA with DN: %s\n", cfg.CA.Root.DN)
			}
			
			filename := cfg.CA.Root.File
			if filename == "" {
				filename = "root-ca"
			}
			// Remove .pem extension if present as it will be added automatically
			filename = removeExtension(filename, ".pem")
			
			rootCA, err = certManager.GenerateCAWithConfig(
				cfg.CA.Root.DN,
				cfg.CA.Root.KeySize,
				cfg.CA.Root.ValidityDays,
				filename,
				cfg.CA.Root.PKPassword,
				cfg.CA.Root.CRLDistributionPoints,
			)
			if err != nil {
				return fmt.Errorf("failed to create root CA: %w", err)
			}
			
			fmt.Printf("✓ Root CA created: %s\n", filepath.Join(outputDir, filename+".pem"))
		}
		
		// Create intermediate CA if configured
		if cfg.CA.Intermediate.DN != "" {
			if rootCA == nil {
				return fmt.Errorf("root CA must be created before intermediate CA")
			}
			
			if verbose {
				fmt.Printf("Creating intermediate CA with DN: %s\n", cfg.CA.Intermediate.DN)
			}
			
			filename := "signing-ca"
			
			// For intermediate CA, we need to sign it with the root CA
			intermediateCA, err := certManager.GenerateCAWithConfig(
				cfg.CA.Intermediate.DN,
				cfg.CA.Intermediate.KeySize,
				cfg.CA.Intermediate.ValidityDays,
				filename,
				cfg.CA.Intermediate.PKPassword,
				cfg.CA.Intermediate.CRLDistributionPoints,
			)
			if err != nil {
				return fmt.Errorf("failed to create intermediate CA: %w", err)
			}
			
			fmt.Printf("✓ Intermediate CA created: %s\n", filepath.Join(outputDir, filename+".pem"))
			
			// Use intermediate CA for future certificate signing
			rootCA = intermediateCA
		}
		
		// Generate CA documentation
		configGen := config.NewConfigGenerator(cfg, outputDir)
		if err := configGen.GenerateCAReadme(certManager.GetPasswords()); err != nil {
			return fmt.Errorf("failed to generate CA documentation: %w", err)
		}
		
		fmt.Println("Certificate Authority creation completed successfully!")
		return nil
}

func init() {
	// No longer registering as subcommand - using flags instead
}

// removeExtension removes the specified extension from filename if present
func removeExtension(filename, ext string) string {
	if len(filename) > len(ext) && filename[len(filename)-len(ext):] == ext {
		return filename[:len(filename)-len(ext)]
	}
	return filename
}
