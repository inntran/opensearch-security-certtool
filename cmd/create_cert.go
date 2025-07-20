package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/inntran/opensearch-security-certtool/internal/cert"
)

// createCertCmd represents the create-cert command
var createCertCmd = &cobra.Command{
	Use:   "create-cert",
	Short: "Create certificates using an existing or newly created local certificate authority",
	Long: `Creates node and client certificates signed by the Certificate Authority.
This command will generate certificates for all nodes and clients defined in the configuration file.

Node certificates include Subject Alternative Names (SANs) for DNS names and IP addresses.
Client certificates are configured for client authentication.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Creating certificates...")
		
		// Create output directory if it doesn't exist
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
		
		// Load or create CA
		var rootCA *cert.CAInfo
		
		// Try to load existing CA first
		caFile := cfg.CA.Root.File
		if caFile == "" {
			caFile = "root-ca"
		}
		caFile = removeExtension(caFile, ".pem")
		
		caPath := filepath.Join(outputDir, caFile+".pem")
		keyPath := filepath.Join(outputDir, caFile+".key")
		
		if _, err := os.Stat(caPath); os.IsNotExist(err) {
			// CA doesn't exist, create it
			if verbose {
				fmt.Println("CA not found, creating new CA...")
			}
			
			rootCA, err = certManager.GenerateCA(
				cfg.CA.Root.DN,
				cfg.CA.Root.KeySize,
				cfg.CA.Root.ValidityDays,
				caFile,
			)
			if err != nil {
				return fmt.Errorf("failed to create CA: %w", err)
			}
			fmt.Printf("✓ Root CA created: %s\n", caPath)
		} else {
			// Load existing CA
			if verbose {
				fmt.Printf("Loading existing CA from: %s\n", caPath)
			}
			
			rootCA, err = loadCA(caPath, keyPath)
			if err != nil {
				return fmt.Errorf("failed to load CA: %w", err)
			}
		}
		
		// Handle intermediate CA if configured
		if cfg.CA.Intermediate.DN != "" {
			intermediatePath := filepath.Join(outputDir, "signing-ca.pem")
			intermediateKeyPath := filepath.Join(outputDir, "signing-ca.key")
			
			if _, err := os.Stat(intermediatePath); os.IsNotExist(err) {
				// Create intermediate CA
				if verbose {
					fmt.Println("Creating intermediate CA...")
				}
				
				intermediateCA, err := certManager.GenerateCA(
					cfg.CA.Intermediate.DN,
					cfg.CA.Intermediate.KeySize,
					cfg.CA.Intermediate.ValidityDays,
					"signing-ca",
				)
				if err != nil {
					return fmt.Errorf("failed to create intermediate CA: %w", err)
				}
				fmt.Printf("✓ Intermediate CA created: %s\n", intermediatePath)
				rootCA = intermediateCA
			} else {
				// Load existing intermediate CA
				if verbose {
					fmt.Printf("Loading existing intermediate CA from: %s\n", intermediatePath)
				}
				
				rootCA, err = loadCA(intermediatePath, intermediateKeyPath)
				if err != nil {
					return fmt.Errorf("failed to load intermediate CA: %w", err)
				}
			}
		}
		
		// Generate node certificates
		for _, node := range cfg.Nodes {
			if verbose {
				fmt.Printf("Creating certificate for node: %s\n", node.Name)
			}
			
			dnsNames := node.GetDNSNames()
			ipAddresses := node.GetIPAddresses()
			
			err := certManager.GenerateNodeCertificate(
				rootCA,
				node.DN,
				dnsNames,
				ipAddresses,
				cfg.Defaults.ValidityDays,
				node.Name,
			)
			if err != nil {
				return fmt.Errorf("failed to create certificate for node %s: %w", node.Name, err)
			}
			
			fmt.Printf("✓ Node certificate created: %s\n", node.Name)
			
			// Generate HTTP certificate if enabled
			if cfg.Defaults.HTTPSEnabled && !cfg.Defaults.ReuseTransportCertificates {
				httpName := node.Name + "_http"
				err := certManager.GenerateNodeCertificate(
					rootCA,
					node.DN,
					dnsNames,
					ipAddresses,
					cfg.Defaults.ValidityDays,
					httpName,
				)
				if err != nil {
					return fmt.Errorf("failed to create HTTP certificate for node %s: %w", node.Name, err)
				}
				fmt.Printf("✓ HTTP certificate created: %s\n", httpName)
			}
		}
		
		// Generate client certificates
		for _, client := range cfg.Clients {
			if verbose {
				fmt.Printf("Creating certificate for client: %s\n", client.Name)
			}
			
			err := certManager.GenerateClientCertificate(
				rootCA,
				client.DN,
				cfg.Defaults.ValidityDays,
				client.Name,
			)
			if err != nil {
				return fmt.Errorf("failed to create certificate for client %s: %w", client.Name, err)
			}
			
			clientType := "Client"
			if client.Admin {
				clientType = "Admin client"
			}
			fmt.Printf("✓ %s certificate created: %s\n", clientType, client.Name)
		}
		
		fmt.Println("Certificate creation completed successfully!")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(createCertCmd)
}

// loadCA loads an existing CA certificate and private key
func loadCA(certPath, keyPath string) (*cert.CAInfo, error) {
	// Read certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	
	// Read private key file
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	
	return cert.LoadCAFromPEM(certPEM, keyPEM)
}
