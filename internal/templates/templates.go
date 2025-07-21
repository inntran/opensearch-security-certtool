package templates

// CA README template
const CAReadmeTemplate = `The private keys of the root certificate and/or the signing certificate have been saved encrypted with an auto-generated password.
In order to use these new passwords later again with this tool, you must edit the tool config file and set the new passwords there.

ca:
  root:
    pkPassword: {{.RootPassword}}{{if .HasIntermediate}}
  intermediate:
    pkPassword: {{.IntermediatePassword}}{{end}}
`

// Client certificates readme template
const ClientReadmeTemplate = `Client certificates are used to authenticate REST clients against your authentication backend.
Thus, the users represented by the client certificates must be also present in your authentication backend.

See https://opensearch.org/docs/latest/security/authentication-backends/client-cert/ for more on this topic.

{{range .Clients}}
{{.DN}} Password: {{.Password}}
{{end}}`

// Node configuration header template
const NodeConfigHeaderTemplate = `# This is a configuration snippet for the node {{.NodeName}}
# This snippet needs to be inserted into the file config/opensearch.yml of the respective node.
# If the config file already contains OpenSearch Security configuration, this needs to be replaced.
# Furthermore, you need to copy the files referenced below into the same directory.
# Please refer to https://opensearch.org/docs/latest/security/configuration/tls/ for further configuration of your installation.`

// Configuration constants
const (
	// File extensions
	CertFileExt   = ".pem"
	KeyFileExt    = ".key"
	ConfigFileExt = "_opensearch_config_snippet.yml"

	// File names
	RootCAFile         = "root-ca"
	IntermediateCAFile = "signing-ca"
	ClientReadmeFile   = "client-certificates.readme"
	CAReadmeFile       = "root-ca.readme"

	// YAML field names
	TransportCertField            = "plugins.security.ssl.transport.pemcert_filepath"
	TransportKeyField             = "plugins.security.ssl.transport.pemkey_filepath"
	TransportPasswordField        = "plugins.security.ssl.transport.pemkey_password"
	TransportTrustedCAsField      = "plugins.security.ssl.transport.pemtrustedcas_filepath"
	TransportHostnameVerifyField  = "plugins.security.ssl.transport.enforce_hostname_verification"
	TransportResolveHostnameField = "plugins.security.ssl.transport.resolve_hostname"

	HTTPEnabledField    = "plugins.security.ssl.http.enabled"
	HTTPCertField       = "plugins.security.ssl.http.pemcert_filepath"
	HTTPKeyField        = "plugins.security.ssl.http.pemkey_filepath"
	HTTPPasswordField   = "plugins.security.ssl.http.pemkey_password"
	HTTPTrustedCAsField = "plugins.security.ssl.http.pemtrustedcas_filepath"

	NodesDNField = "plugins.security.nodes_dn"
	AdminDNField = "plugins.security.authcz.admin_dn"
)

// Template data structures
type CAReadmeData struct {
	RootPassword         string
	IntermediatePassword string
	HasIntermediate      bool
}

type ClientReadmeData struct {
	Clients []ClientData
}

type ClientData struct {
	DN       string
	Password string
}

type NodeConfigHeaderData struct {
	NodeName string
}
