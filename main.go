package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
)

// Google Internet Authority G2 intermediate, expires 31 Dec 2016
const GIA_G2_SHA256 = "A4124FDAF9CAC7BAEE1CAB32E3225D746500C09F3CF3EBB253EF3FBB088AFD34"

// The official Golang binaries bucket
const baseStorageURL = "https://storage.googleapis.com/golang"

type DownloadOptions struct {
	version  string
	platform string
	output   string
	verbose  bool
}

// Note: pretty much only works for talking to Google & has a very clear fingerprint.
var sillyTLSConfig = tls.Config{
	RootCAs: nil, // use system bundle
	CipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	},
	MinVersion:               tls.VersionTLS12,
	PreferServerCipherSuites: false,
	CurvePreferences: []tls.CurveID{
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	},
}

func dialTLSWithPin(network, addr string) (net.Conn, error) {
	conn, err := tls.Dial(network, addr, &sillyTLSConfig)
	if err != nil {
		return nil, err
	}
	certAsExpected := false
	verifiedChains := conn.ConnectionState().VerifiedChains
	for _, chain := range verifiedChains {
		for _, cert := range chain {
			if cert.IsCA && cert.Subject.CommonName == "Google Internet Authority G2" && cert.SignatureAlgorithm == x509.SHA256WithRSA {
				digest := sha256.Sum256(cert.Raw)
				decodedPin, err := hex.DecodeString(GIA_G2_SHA256)
				if err != nil {
					return nil, err
				}
				if bytes.Equal(digest[:], decodedPin) {
					certAsExpected = true
				} else {
					return nil, errors.New("The Google intermediate had the wrong hash. Suggest you flee.")
				}
			}
		}
	}
	if certAsExpected {
		return conn, nil
	}
	return nil, errors.New("Failed to locate Google intermediate.")
}

func NewOnlyGoogleTransport() *http.Transport {
	return &http.Transport{
		DialTLS: dialTLSWithPin,
	}
}

func downloadPackage(opts *DownloadOptions) error {
	packageName := fmt.Sprintf("go%s.%s.tar.gz", opts.version, opts.platform)
	packageURL := fmt.Sprintf("%s/%s", baseStorageURL, packageName)
	hashURL := fmt.Sprintf("%s/%s.sha256", baseStorageURL, packageName)
	if opts.verbose {
		log.Printf("Downloading %s", packageURL)
		log.Printf("Downloading %s", hashURL)
	}

	onlyTalksToGoogle := NewOnlyGoogleTransport()

	// Get the hash first- if it fails, the package is useless.
	hashRequest, err := http.NewRequest("GET", hashURL, nil)
	if err != nil {
		return fmt.Errorf("Could not construct hash request: %v", err)
	}
	resp, err := onlyTalksToGoogle.RoundTrip(hashRequest)
	defer resp.Body.Close()
	if err != nil {
		return fmt.Errorf("Failed to fetch hash: %v", err)
	}
	hashBuffer := new(bytes.Buffer)
	n, err := io.Copy(hashBuffer, resp.Body)
	if err != nil {
		return fmt.Errorf("Failed to extract hash response: %v", err)
	}
	if n != 64 {
		return fmt.Errorf("The returned SHA256 hash was not the right size: %d bytes", n)
	}

	if opts.verbose {
		log.Printf("Got hash: %s", hashBuffer.String())
	}

	// Download the binary and check its hash before writing out.
	packageRequest, err := http.NewRequest("GET", packageURL, nil)
	if err != nil {
		return fmt.Errorf("Could not construct package request: %v", err)
	}
	resp, err = onlyTalksToGoogle.RoundTrip(packageRequest)
	defer resp.Body.Close()
	if err != nil {
		return fmt.Errorf("Failed to fetch package: %v", err)
	}
	packageBuffer := new(bytes.Buffer)
	_, err = io.Copy(packageBuffer, resp.Body)
	if err != nil {
		return fmt.Errorf("Failed to extract package response: %v", err)
	}

	decodedDigest, err := hex.DecodeString(hashBuffer.String())
	if err != nil {
		return fmt.Errorf("could not get bytes from hex digest: %v", err)
	}

	packageDigest := sha256.Sum256(packageBuffer.Bytes())
	if bytes.Equal(decodedDigest, packageDigest[:]) {
		if opts.output != "" {
			packageName = opts.output
		}
		if opts.verbose {
			log.Printf("Writing to %s", packageName)
		}
		return writeFile(packageName, packageBuffer.Bytes())
	} else {
		return fmt.Errorf("Package didn't match expected hash: %s", hex.EncodeToString(packageDigest[:]))
	}
}

func writeFile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, 0644)
}

func main() {
	opts := &DownloadOptions{}
	flag.StringVar(&opts.version, "version", "1.6.2", "the go version to download")
	flag.StringVar(&opts.platform, "platform", "linux-amd64", "the build platform")
	flag.StringVar(&opts.output, "o", "", "output filename")
	flag.BoolVar(&opts.verbose, "v", false, "toggles logging")
	flag.Parse()

	err := downloadPackage(opts)
	if err != nil {
		log.Fatal(err)
	}
}
