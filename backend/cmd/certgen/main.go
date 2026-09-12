package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kypeli/mtls-poc/backend/internal/ca"
)

func main() {
	outDir := flag.String("out-dir", "certs", "Directory where certificates will be written")
	caCN := flag.String("ca-cn", "Hardware mTLS PoC Root CA", "Common Name for Root CA")
	serverCN := flag.String("server-cn", "localhost", "Common Name for Server TLS certificate")
	force := flag.Bool("force", false, "Delete and regenerate existing certificate and key files")
	androidCAPath := flag.String("android-ca-path", filepath.Join("..", "android", "app", "src", "debug", "res", "raw", "debug_ca.crt"),
		"Path where the Root CA is copied for Android debug trust (skipped when the target directory does not exist)")
	flag.Parse()

	paths := ca.BootstrapPaths{
		CaCertPath:     filepath.Join(*outDir, "ca.crt"),
		CaKeyPath:      filepath.Join(*outDir, "ca.key"),
		ServerCertPath: filepath.Join(*outDir, "server.crt"),
		ServerKeyPath:  filepath.Join(*outDir, "server.key"),
	}

	anyExist := false
	for _, path := range []string{paths.CaCertPath, paths.CaKeyPath, paths.ServerCertPath, paths.ServerKeyPath} {
		if _, err := os.Stat(path); err == nil {
			anyExist = true
			break
		}
	}
	if anyExist {
		if !*force {
			fmt.Printf("Certificates already exist in %s. Use -force to regenerate.\n", *outDir)
			return
		}
		for _, path := range []string{paths.CaCertPath, paths.CaKeyPath, paths.ServerCertPath, paths.ServerKeyPath} {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Failed to remove %s: %v\n", path, err)
				os.Exit(1)
			}
		}
	}

	generated, err := ca.BootstrapCertificates(ca.BootstrapOptions{
		Paths:          paths,
		CaCN:           *caCN,
		ServerCN:       *serverCN,
		CaValidity:     10 * 365 * 24 * time.Hour,
		ServerValidity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to bootstrap certificates: %v\n", err)
		os.Exit(1)
	}

	copyAndroidCA(*androidCAPath, generated.CaCertPath)

	fmt.Printf("Certificates generated successfully:\n")
	fmt.Printf("  • CA Key:      %s\n", generated.CaKeyPath)
	fmt.Printf("  • CA Cert:     %s\n", generated.CaCertPath)
	fmt.Printf("  • Server Key:  %s\n", generated.ServerKeyPath)
	fmt.Printf("  • Server Cert: %s\n", generated.ServerCertPath)
}

// copyAndroidCA copies the generated Root CA into the Android debug res folder
// so debug builds trust the local server certificate. It is skipped when the
// target directory does not exist.
func copyAndroidCA(targetPath, caCertPath string) {
	if targetPath == "" {
		return
	}
	targetDir := filepath.Dir(targetPath)
	if info, err := os.Stat(targetDir); err != nil || !info.IsDir() {
		fmt.Printf("Skipped Android debug CA copy: %s does not exist\n", targetDir)
		return
	}
	data, err := os.ReadFile(caCertPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read %s for Android debug CA copy: %v\n", caCertPath, err)
		os.Exit(1)
	}
	if err := os.WriteFile(targetPath, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", targetPath, err)
		os.Exit(1)
	}
	fmt.Printf("Android debug CA copied to %s\n", targetPath)
}
