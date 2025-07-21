package cert

import (
	"testing"
)

func TestNewPasswordManager(t *testing.T) {
	tests := []struct {
		name           string
		inputLength    int
		expectedLength int
	}{
		{
			name:           "valid_length",
			inputLength:    16,
			expectedLength: 16,
		},
		{
			name:           "minimum_length_enforced",
			inputLength:    8,
			expectedLength: 12, // Should be increased to minimum
		},
		{
			name:           "zero_length_uses_minimum",
			inputLength:    0,
			expectedLength: 12,
		},
		{
			name:           "negative_length_uses_minimum",
			inputLength:    -5,
			expectedLength: 12,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := NewPasswordManager(tt.inputLength)
			if pm.length != tt.expectedLength {
				t.Errorf("Expected length %d, got %d", tt.expectedLength, pm.length)
			}
		})
	}
}

func TestGeneratePassword(t *testing.T) {

	tests := []struct {
		name           string
		passwordLength int
	}{
		{"length_12", 12},
		{"length_16", 16},
		{"length_24", 24},
		{"length_32", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := NewPasswordManager(tt.passwordLength)
			password, err := pm.GeneratePassword()

			if err != nil {
				t.Fatalf("GeneratePassword() error = %v", err)
			}

			// Check password length
			if len(password) != tt.passwordLength {
				t.Errorf("Expected password length %d, got %d", tt.passwordLength, len(password))
			}

			// Check password contains only valid characters
			validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
			for _, char := range password {
				found := false
				for _, validChar := range validChars {
					if char == validChar {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Password contains invalid character: %c", char)
				}
			}

			// Check password contains different character types
			hasLower := false
			hasUpper := false
			hasDigit := false

			for _, char := range password {
				switch {
				case char >= 'a' && char <= 'z':
					hasLower = true
				case char >= 'A' && char <= 'Z':
					hasUpper = true
				case char >= '0' && char <= '9':
					hasDigit = true
				}
			}

			// For longer passwords, we expect all character types
			if tt.passwordLength >= 16 {
				if !hasLower {
					t.Error("Password should contain lowercase letters")
				}
				if !hasUpper {
					t.Error("Password should contain uppercase letters")
				}
				if !hasDigit {
					t.Error("Password should contain digits")
				}
			}
		})
	}
}

func TestGeneratePasswordUniqueness(t *testing.T) {
	pm := NewPasswordManager(16)
	passwords := make(map[string]bool)
	numPasswords := 100

	for i := 0; i < numPasswords; i++ {
		password, err := pm.GeneratePassword()
		if err != nil {
			t.Fatalf("GeneratePassword() error = %v", err)
		}

		if passwords[password] {
			t.Errorf("Generated duplicate password: %s", password)
		}
		passwords[password] = true
	}

	if len(passwords) != numPasswords {
		t.Errorf("Expected %d unique passwords, got %d", numPasswords, len(passwords))
	}
}

func TestNewCertificatePasswords(t *testing.T) {
	cp := NewCertificatePasswords()

	if cp.NodePasswords == nil {
		t.Error("Expected NodePasswords map to be initialized")
	}
	if cp.ClientPasswords == nil {
		t.Error("Expected ClientPasswords map to be initialized")
	}

	// Check maps are empty initially
	if len(cp.NodePasswords) != 0 {
		t.Errorf("Expected empty NodePasswords map, got %d entries", len(cp.NodePasswords))
	}
	if len(cp.ClientPasswords) != 0 {
		t.Errorf("Expected empty ClientPasswords map, got %d entries", len(cp.ClientPasswords))
	}
}

func TestSetNodePasswords(t *testing.T) {
	cp := NewCertificatePasswords()

	tests := []struct {
		name              string
		nodeName          string
		transportPassword string
		httpPassword      string
	}{
		{
			name:              "both_passwords",
			nodeName:          "node1",
			transportPassword: "transport123",
			httpPassword:      "http123",
		},
		{
			name:              "transport_only",
			nodeName:          "node2",
			transportPassword: "transport456",
			httpPassword:      "",
		},
		{
			name:              "http_only",
			nodeName:          "node3",
			transportPassword: "",
			httpPassword:      "http456",
		},
		{
			name:              "empty_passwords",
			nodeName:          "node4",
			transportPassword: "",
			httpPassword:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp.SetNodePasswords(tt.nodeName, tt.transportPassword, tt.httpPassword)

			nodeInfo, exists := cp.NodePasswords[tt.nodeName]
			if !exists {
				t.Errorf("Expected node %s to be stored", tt.nodeName)
				return
			}

			if nodeInfo.TransportPassword != tt.transportPassword {
				t.Errorf("Expected transport password %s, got %s", tt.transportPassword, nodeInfo.TransportPassword)
			}
			if nodeInfo.HTTPPassword != tt.httpPassword {
				t.Errorf("Expected HTTP password %s, got %s", tt.httpPassword, nodeInfo.HTTPPassword)
			}
		})
	}
}

func TestSetClientPassword(t *testing.T) {
	cp := NewCertificatePasswords()

	tests := []struct {
		name       string
		clientName string
		password   string
	}{
		{
			name:       "admin_client",
			clientName: "admin",
			password:   "admin123",
		},
		{
			name:       "kibana_client",
			clientName: "kibana",
			password:   "kibana456",
		},
		{
			name:       "empty_password",
			clientName: "test",
			password:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp.SetClientPassword(tt.clientName, tt.password)

			storedPassword, exists := cp.ClientPasswords[tt.clientName]
			if !exists {
				t.Errorf("Expected client %s to be stored", tt.clientName)
				return
			}

			if storedPassword != tt.password {
				t.Errorf("Expected password %s, got %s", tt.password, storedPassword)
			}
		})
	}
}

func TestGetNodeTransportPassword(t *testing.T) {
	cp := NewCertificatePasswords()

	// Set up test data
	cp.SetNodePasswords("node1", "transport123", "http123")
	cp.SetNodePasswords("node2", "transport456", "")

	tests := []struct {
		name     string
		nodeName string
		expected string
	}{
		{
			name:     "existing_node_with_transport",
			nodeName: "node1",
			expected: "transport123",
		},
		{
			name:     "existing_node_transport_only",
			nodeName: "node2",
			expected: "transport456",
		},
		{
			name:     "non_existent_node",
			nodeName: "nonexistent",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cp.GetNodeTransportPassword(tt.nodeName)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetNodeHTTPPassword(t *testing.T) {
	cp := NewCertificatePasswords()

	// Set up test data
	cp.SetNodePasswords("node1", "transport123", "http123")
	cp.SetNodePasswords("node2", "", "http456")

	tests := []struct {
		name     string
		nodeName string
		expected string
	}{
		{
			name:     "existing_node_with_http",
			nodeName: "node1",
			expected: "http123",
		},
		{
			name:     "existing_node_http_only",
			nodeName: "node2",
			expected: "http456",
		},
		{
			name:     "non_existent_node",
			nodeName: "nonexistent",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cp.GetNodeHTTPPassword(tt.nodeName)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetClientPassword(t *testing.T) {
	cp := NewCertificatePasswords()

	// Set up test data
	cp.SetClientPassword("admin", "admin123")
	cp.SetClientPassword("kibana", "kibana456")

	tests := []struct {
		name       string
		clientName string
		expected   string
	}{
		{
			name:       "existing_admin",
			clientName: "admin",
			expected:   "admin123",
		},
		{
			name:       "existing_kibana",
			clientName: "kibana",
			expected:   "kibana456",
		},
		{
			name:       "non_existent_client",
			clientName: "nonexistent",
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cp.GetClientPassword(tt.clientName)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestNodePasswordInfoStructure(t *testing.T) {
	info := NodePasswordInfo{
		TransportPassword: "transport123",
		HTTPPassword:      "http123",
	}

	if info.TransportPassword != "transport123" {
		t.Errorf("Expected transport password 'transport123', got %s", info.TransportPassword)
	}
	if info.HTTPPassword != "http123" {
		t.Errorf("Expected HTTP password 'http123', got %s", info.HTTPPassword)
	}
}

func TestCertificatePasswordsOverwrite(t *testing.T) {
	cp := NewCertificatePasswords()

	// Set initial passwords
	cp.SetNodePasswords("node1", "old_transport", "old_http")
	cp.SetClientPassword("admin", "old_admin")

	// Verify initial values
	if cp.GetNodeTransportPassword("node1") != "old_transport" {
		t.Error("Initial transport password not set correctly")
	}
	if cp.GetClientPassword("admin") != "old_admin" {
		t.Error("Initial client password not set correctly")
	}

	// Overwrite with new values
	cp.SetNodePasswords("node1", "new_transport", "new_http")
	cp.SetClientPassword("admin", "new_admin")

	// Verify new values
	if cp.GetNodeTransportPassword("node1") != "new_transport" {
		t.Error("Transport password not overwritten correctly")
	}
	if cp.GetNodeHTTPPassword("node1") != "new_http" {
		t.Error("HTTP password not overwritten correctly")
	}
	if cp.GetClientPassword("admin") != "new_admin" {
		t.Error("Client password not overwritten correctly")
	}
}
