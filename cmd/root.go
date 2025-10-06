package cmd

import (
	"fmt"

	"github.com/inntran/opensearch-security-certtool/internal/cert"
	"github.com/inntran/opensearch-security-certtool/internal/config"
	"github.com/inntran/opensearch-security-certtool/internal/logger"
	"github.com/spf13/cobra"
)

var (
	cfgFile   string
	outputDir string
	overwrite bool
	verbose   bool
	force     bool

	// Action flags (mutually exclusive)
	createCA   bool
	createCert bool
	createCSR  bool

	cfg         *config.Config
	certManager *cert.CertificateManager
	log         *logger.Logger
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "opensearch-security-certtool",
	Short: "SSL/TLS certificate generation and validation tool for OpenSearch Security",
	Long: `OpenSearch Security Certificate Tool is a command-line utility for generating
and managing SSL/TLS certificates for OpenSearch clusters.

Usage Options:
1. Command-based (Java tool short form compatibility):
   opensearch-security-certtool ca --config config.yml
   opensearch-security-certtool crt --config config.yml
   opensearch-security-certtool csr --config config.yml

2. Flag-based (Java tool long form compatibility):
   opensearch-security-certtool --create-ca --config config.yml
   opensearch-security-certtool --create-cert --config config.yml
   opensearch-security-certtool --create-csr --config config.yml

For flag-based usage, you must specify exactly one action flag and a config file.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip initialization for help and version commands
		if cmd.Name() == "help" || cmd.Name() == "version" {
			return nil
		}

		// Initialize config and certManager for all commands that need them
		return initializeConfig()
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check that at least one action flag is specified
		actionCount := 0
		if createCA {
			actionCount++
		}
		if createCert {
			actionCount++
		}
		if createCSR {
			actionCount++
		}

		if actionCount == 0 {
			return fmt.Errorf("you must specify at least one action: --create-ca, --create-cert, or --create-csr")
		}

		if actionCount > 1 {
			return fmt.Errorf("only one action can be specified at a time")
		}

		return executeAction()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags (persistent so they work with subcommands)
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Path to the config file")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "target", "t", "out", "Path to the target directory")
	rootCmd.PersistentFlags().BoolVarP(&overwrite, "overwrite", "o", false, "Overwrite existing files")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable detailed output")
	rootCmd.PersistentFlags().BoolVarP(&force, "force", "f", false,
		"Force certificate generation despite validation errors")

	// Action flags (long form for compatibility)
	rootCmd.Flags().BoolVar(&createCA, "create-ca", false, "Create a new certificate authority")
	rootCmd.Flags().BoolVar(&createCert, "create-cert", false,
		"Create certificates using an existing or newly created local certificate authority")
	rootCmd.Flags().BoolVar(&createCSR, "create-csr", false, "Create certificate signing requests")
}

// initializeConfig loads configuration and initializes global variables
func initializeConfig() error {
	// Load configuration
	if cfgFile == "" {
		return fmt.Errorf("config file is required, use --config flag")
	}

	var err error
	cfg, err = config.LoadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Validate configuration (skip if force is enabled)
	if !force {
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("config validation failed: %w", err)
		}
	}

	// Initialize logger
	log = logger.New(verbose)

	// Initialize certificate manager
	certManager = cert.NewCertificateManager(outputDir, cfg.Defaults.GeneratedPasswordLength, log)

	if verbose {
		fmt.Printf("Loaded config from: %s\n", cfgFile)
		fmt.Printf("Output directory: %s\n", outputDir)
	}

	return nil
}

// executeAction handles the flag-based action execution
func executeAction() error {
	// Execute the requested action
	switch {
	case createCA:
		return createCACommand()
	case createCert:
		return createCertCommand()
	case createCSR:
		return fmt.Errorf("certificate signing request generation is not yet implemented")
	default:
		return nil
	}
}
