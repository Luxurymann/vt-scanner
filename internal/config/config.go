package config

import (
	"bufio"
	"errors"
	"os"
	"strings"
)

// Config holds the application configuration
type Config struct {
	VTAPIKey string
}

// Load reads config from environment variables and optionally from an .env file
func Load(envPath string) (*Config, error) {
	// Try loading .env if it exists
	if envPath != "" {
		_ = loadEnvFile(envPath) // Ignore errors if file doesn't exist
	} else {
		_ = loadEnvFile(".env") // Default .env
	}

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		return nil, errors.New("VT_API_KEY is required in environment or .env file")
	}

	return &Config{
		VTAPIKey: apiKey,
	}, nil
}

// loadEnvFile reads a simple .env file and sets environment variables
func loadEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// Remove quotes if present
		val = strings.Trim(val, `"'`)

		if err := os.Setenv(key, val); err != nil {
			return err
		}
	}

	return scanner.Err()
}
