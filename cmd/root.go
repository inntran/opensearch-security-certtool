package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/inntran/opensearch-security-certtool/internal/config"
	"github.com/inntran/opensearch-security-certtool/internal/cert"
)

var (
	cfgFile    string
	outputDir  string
	overwrite  bool
	verbose    bool
	force      bool
	
	cfg *config.Config
	certManager *cert.CertificateManager
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "opensearch-security-certtool",
	Short: "SSL/TLS certificate generation and validation tool for OpenSearch Security",
	Long: `OpenSearch Security Certificate Tool is a command-line utility for generating
and managing SSL/TLS certificates for OpenSearch clusters.

Features:
- Create Certificate Authorities (root and intermediate)
- Generate node certificates for OpenSearch clusters
- Generate client certificates for authentication
- Create Certificate Signing Requests (CSRs)
- Validate certificates and configurations

Example usage:
  opensearch-security-certtool --create-ca --config config.yml
  opensearch-security-certtool --create-cert --config config.yml
  opensearch-security-certtool --create-csr --config config.yml`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip config loading for help and version commands
		if cmd.Name() == "help" || cmd.Name() == "version" {
			return nil
		}
		
		// Load configuration
		if cfgFile == "" {
			return fmt.Errorf("config file is required, use --config flag")
		}
		
		var err error
		cfg, err = config.LoadConfig(cfgFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		
		// Validate configuration
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("config validation failed: %w", err)
		}
		
		// Initialize certificate manager
		certManager = cert.NewCertificateManager(outputDir)
		
		if verbose {
			fmt.Printf("Loaded config from: %s\n", cfgFile)
			fmt.Printf("Output directory: %s\n", outputDir)
		}
		
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Path to the config file (required)")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "target", "t", "out", "Path to the target directory")
	rootCmd.PersistentFlags().BoolVarP(&overwrite, "overwrite", "o", false, "Overwrite existing files")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable detailed output")
	rootCmd.PersistentFlags().BoolVarP(&force, "force", "f", false, "Force certificate generation despite validation errors")
	
	// Mark config as required
	rootCmd.MarkPersistentFlagRequired("config")
}
