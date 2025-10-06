package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/inntran/opensearch-security-certtool/internal/config"
	"github.com/inntran/opensearch-security-certtool/internal/cert"
)

// generateConfigCmd represents the generate-config command
var generateConfigCmd = &cobra.Command{
	Use:   "generate-config",
	Short: "Generate OpenSearch configuration snippets for existing certificates",
	Long: `Generates OpenSearch Security configuration snippets for nodes and clients.
This command is useful when you already have certificates and need to generate
the corresponding OpenSearch configuration files.

The generated configuration snippets should be added to each node's opensearch.yml file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Generating OpenSearch configuration snippets...")
		
		// Create output directory if it doesn't exist
		if err := os.MkdirAll(outputDir, 0750); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
		
		// Generate configuration snippets
		configGen := config.NewConfigGenerator(cfg, outputDir)
		
		// Create empty password collection for existing certificates
		passwords := cert.NewCertificatePasswords()
		
		if err := configGen.GenerateNodeConfigs(passwords); err != nil {
			return fmt.Errorf("failed to generate node configurations: %w", err)
		}
		
		if verbose {
			fmt.Printf("✓ Generated configuration snippets for %d nodes\n", len(cfg.Nodes))
		}
		
		if err := configGen.GenerateClientReadme(passwords); err != nil {
			return fmt.Errorf("failed to generate client documentation: %w", err)
		}
		
		if len(cfg.Clients) > 0 {
			if verbose {
				fmt.Printf("✓ Generated client documentation for %d clients\n", len(cfg.Clients))
			}
		}
		
		fmt.Println("✓ OpenSearch configuration generation completed!")
		fmt.Printf("Generated files in: %s\n", outputDir)
		
		// List generated files
		if verbose {
			fmt.Println("\nGenerated files:")
			for _, node := range cfg.Nodes {
				fmt.Printf("  - %s_opensearch_config_snippet.yml\n", node.Name)
			}
			if len(cfg.Clients) > 0 {
				fmt.Printf("  - client-certificates.md\n")
			}
		}
		
		return nil
	},
}

func init() {
	// No longer registering as subcommand - using flags instead
}
