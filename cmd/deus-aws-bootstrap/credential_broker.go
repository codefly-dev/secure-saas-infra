package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type credentialEnvelope struct {
	Version                int    `json:"Version"`
	AccessKeyID            string `json:"AccessKeyId"`
	SecretAccessKey        string `json:"SecretAccessKey"`
	SessionToken           string `json:"SessionToken"`
	Expiration             string `json:"Expiration"`
	PulumiAccessToken      string `json:"PulumiAccessToken,omitempty"`
	PulumiConfigPassphrase string `json:"PulumiConfigPassphrase,omitempty"`
}

type localCredentialBroker struct {
	listener    net.Listener
	server      *http.Server
	awsToken    string
	pulumiToken string
	uri         string
}

func extractCredentialFD(args []string) ([]string, int, error) {
	filtered := make([]string, 0, len(args))
	fd := -1
	for index := 0; index < len(args); index++ {
		if args[index] != "--credential-fd" {
			filtered = append(filtered, args[index])
			continue
		}
		if fd != -1 || index+1 >= len(args) {
			return nil, -1, errors.New("credential launcher requires one --credential-fd <number>")
		}
		parsed, err := strconv.Atoi(args[index+1])
		if err != nil || parsed < 0 || parsed > 1024 || parsed == 1 || parsed == 2 {
			return nil, -1, errors.New("credential FD must be standard input or an inherited descriptor from 3 through 1024")
		}
		fd = parsed
		index++
	}
	if fd == -1 {
		return nil, -1, errors.New("credential launcher requires --credential-fd <number>")
	}
	return filtered, fd, nil
}

func runCredentialEnvelope(args, inherited []string, stdout io.Writer, now time.Time) error {
	if err := requireLinuxExecution(); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return errors.New("credential envelope creation as OS root is forbidden")
	}
	if err := requirePtraceIsolation(); err != nil {
		return err
	}
	if err := rejectInheritedCredentialMaterial(inherited); err != nil {
		return err
	}
	if err := requireInstalledLauncher(); err != nil {
		return err
	}
	options, err := parseCredentialEnvelopeArgs(args)
	if err != nil {
		return err
	}
	output, ok := stdout.(*os.File)
	if !ok {
		return errors.New("credential envelope output must be an anonymous pipe")
	}
	if err := requireAnonymousPipe(output, "credential envelope output"); err != nil {
		return err
	}
	awsBytes, err := readSecretFD(options.awsFD, "AWS credential", 64*1024)
	if err != nil {
		return err
	}
	session, err := readCredentialEnvelope(strings.NewReader(string(awsBytes)), "access-provisioner", now)
	zeroBytes(awsBytes)
	if err != nil {
		return err
	}
	if options.mode == "bootstrap" {
		pulumiToken, err := readSecretFD(options.pulumiTokenFD, "Pulumi access token", 8*1024)
		if err != nil {
			return err
		}
		session.PulumiAccessToken = strings.TrimSuffix(string(pulumiToken), "\n")
		zeroBytes(pulumiToken)
		if options.pulumiPassphraseFD != -1 {
			passphrase, err := readSecretFD(options.pulumiPassphraseFD, "Pulumi passphrase", 8*1024)
			if err != nil {
				return err
			}
			session.PulumiConfigPassphrase = strings.TrimSuffix(string(passphrase), "\n")
			zeroBytes(passphrase)
		}
	}
	if err := validateCredentialEnvelope(session, options.mode, now); err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(session); err != nil {
		return fmt.Errorf("write credential envelope: %w", err)
	}
	return nil
}

type credentialEnvelopeOptions struct {
	mode               string
	awsFD              int
	pulumiTokenFD      int
	pulumiPassphraseFD int
}

func parseCredentialEnvelopeArgs(args []string) (credentialEnvelopeOptions, error) {
	result := credentialEnvelopeOptions{awsFD: -1, pulumiTokenFD: -1, pulumiPassphraseFD: -1}
	for index := 0; index < len(args); index += 2 {
		if index+1 >= len(args) {
			return result, errors.New("credential-envelope arguments require values")
		}
		name, value := args[index], args[index+1]
		switch name {
		case "--mode":
			if result.mode != "" {
				return result, errors.New("duplicate credential-envelope mode")
			}
			result.mode = value
		case "--aws-fd", "--pulumi-token-fd", "--pulumi-passphrase-fd":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 3 || parsed > 1024 {
				return result, fmt.Errorf("%s requires a descriptor from 3 through 1024", name)
			}
			target := &result.awsFD
			if name == "--pulumi-token-fd" {
				target = &result.pulumiTokenFD
			} else if name == "--pulumi-passphrase-fd" {
				target = &result.pulumiPassphraseFD
			}
			if *target != -1 {
				return result, fmt.Errorf("duplicate %s", name)
			}
			*target = parsed
		default:
			return result, fmt.Errorf("unknown credential-envelope argument %s", name)
		}
	}
	if (result.mode != "bootstrap" && result.mode != "access-provisioner" && result.mode != "organization-recovery") || result.awsFD == -1 {
		return result, errors.New("credential-envelope requires --mode and --aws-fd")
	}
	if result.mode == "bootstrap" && result.pulumiTokenFD == -1 {
		return result, errors.New("bootstrap credential-envelope requires --pulumi-token-fd")
	}
	if result.mode != "bootstrap" && (result.pulumiTokenFD != -1 || result.pulumiPassphraseFD != -1) {
		return result, errors.New("non-Pulumi credential-envelope mode forbids Pulumi descriptors")
	}
	seen := map[int]bool{}
	for _, fd := range []int{result.awsFD, result.pulumiTokenFD, result.pulumiPassphraseFD} {
		if fd == -1 {
			continue
		}
		if seen[fd] {
			return result, errors.New("credential-envelope descriptors must be distinct")
		}
		seen[fd] = true
	}
	return result, nil
}

func readSecretFD(fd int, label string, maximum int64) ([]byte, error) {
	file := os.NewFile(uintptr(fd), label)
	if file == nil {
		return nil, fmt.Errorf("%s FD is unavailable", label)
	}
	defer file.Close()
	if err := requireAnonymousPipe(file, label); err != nil {
		return nil, err
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(contents) == 0 || int64(len(contents)) > maximum {
		zeroBytes(contents)
		return nil, fmt.Errorf("%s is empty, excessive, or unreadable", label)
	}
	return contents, nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func rejectInheritedCredentialMaterial(entries []string) error {
	for _, entry := range entries {
		name, value, found := strings.Cut(entry, "=")
		if !found || name == "" {
			return errors.New("inherited environment contains a malformed entry")
		}
		if value == "" {
			continue
		}
		switch name {
		case "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
			"AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
			"AWS_CONTAINER_AUTHORIZATION_TOKEN", "PULUMI_ACCESS_TOKEN",
			"PULUMI_CONFIG_PASSPHRASE", "PULUMI_CONFIG_PASSPHRASE_FILE":
			return fmt.Errorf("credential material must arrive only through --credential-fd, not %s", name)
		}
	}
	return nil
}

func readCredentialFD(fd int, entrypoint string, now time.Time) (credentialEnvelope, error) {
	file := os.NewFile(uintptr(fd), "deus-bootstrap-credential-input")
	if file == nil {
		return credentialEnvelope{}, errors.New("credential FD is unavailable")
	}
	defer file.Close()
	if err := requireAnonymousPipe(file, "credential FD"); err != nil {
		return credentialEnvelope{}, err
	}
	return readCredentialEnvelope(file, entrypoint, now)
}

func readCredentialEnvelope(reader io.Reader, entrypoint string, now time.Time) (credentialEnvelope, error) {
	limited := io.LimitReader(reader, 64*1024+1)
	contents, err := io.ReadAll(limited)
	if err != nil {
		return credentialEnvelope{}, fmt.Errorf("read credential envelope: %w", err)
	}
	defer func() {
		for index := range contents {
			contents[index] = 0
		}
	}()
	if len(contents) == 0 || len(contents) > 64*1024 {
		return credentialEnvelope{}, errors.New("credential envelope is empty or excessive")
	}
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	var session credentialEnvelope
	if err := decoder.Decode(&session); err != nil {
		return credentialEnvelope{}, fmt.Errorf("parse credential envelope: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return credentialEnvelope{}, err
	}
	if err := validateCredentialEnvelope(session, entrypoint, now); err != nil {
		return credentialEnvelope{}, err
	}
	return session, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("credential envelope contains trailing JSON")
	}
	return nil
}

func validateCredentialEnvelope(session credentialEnvelope, entrypoint string, now time.Time) error {
	if session.Version != 1 || !validTemporaryAccessKey(session.AccessKeyID) {
		return errors.New("credential envelope does not contain an STS/SSO temporary access key")
	}
	for label, value := range map[string]string{
		"AWS secret access key": session.SecretAccessKey,
		"AWS session token":     session.SessionToken,
	} {
		if len(value) < 16 || len(value) > 8*1024 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("credential envelope contains an invalid %s", label)
		}
	}
	expiration, err := time.Parse(time.RFC3339, session.Expiration)
	if err != nil || !expiration.After(now.Add(5*time.Minute)) || expiration.After(now.Add(65*time.Minute)) {
		return errors.New("credential envelope expiration must be between five and sixty-five minutes")
	}
	if entrypoint == "bootstrap" {
		if len(session.PulumiAccessToken) < 16 || len(session.PulumiAccessToken) > 8*1024 ||
			strings.ContainsAny(session.PulumiAccessToken, "\x00\r\n") ||
			strings.ContainsAny(session.PulumiConfigPassphrase, "\x00\r\n") {
			return errors.New("bootstrap credential envelope requires a bounded Pulumi access token")
		}
	} else if session.PulumiAccessToken != "" || session.PulumiConfigPassphrase != "" {
		return errors.New("non-Pulumi credential envelope must not contain Pulumi secrets")
	}
	return nil
}

func validTemporaryAccessKey(value string) bool {
	if len(value) != 20 || !strings.HasPrefix(value, "ASIA") {
		return false
	}
	for _, character := range value[4:] {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func startCredentialBroker(session credentialEnvelope) (*localCredentialBroker, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start loopback credential broker: %w", err)
	}
	awsToken, err := randomBearerToken()
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("create credential broker authorization: %w", err)
	}
	pulumiToken, err := randomBearerToken()
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("create Pulumi broker authorization: %w", err)
	}
	var awsRequests atomic.Uint32
	var pulumiRequests atomic.Uint32
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		if request.Method != http.MethodGet || request.URL.RawQuery != "" {
			http.Error(response, `{"error":"denied"}`, http.StatusForbidden)
			return
		}
		switch request.URL.Path {
		case "/v1/credentials":
			if request.Header.Get("Authorization") != awsToken || awsRequests.Add(1) > 256 {
				http.Error(response, `{"error":"denied"}`, http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(response).Encode(struct {
				Version         int    `json:"Version"`
				AccessKeyID     string `json:"AccessKeyId"`
				SecretAccessKey string `json:"SecretAccessKey"`
				Token           string `json:"Token"`
				Expiration      string `json:"Expiration"`
			}{session.Version, session.AccessKeyID, session.SecretAccessKey, session.SessionToken, session.Expiration})
		case "/v1/pulumi":
			if request.Header.Get("Authorization") != pulumiToken || pulumiRequests.Add(1) > 8 {
				http.Error(response, `{"error":"denied"}`, http.StatusForbidden)
				return
			}
			if session.PulumiAccessToken == "" {
				http.Error(response, `{"error":"unavailable"}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(response).Encode(struct {
				AccessToken string `json:"accessToken"`
				Passphrase  string `json:"configPassphrase,omitempty"`
			}{session.PulumiAccessToken, session.PulumiConfigPassphrase})
		default:
			http.Error(response, `{"error":"not_found"}`, http.StatusNotFound)
		}
	})
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    8 * 1024,
	}
	broker := &localCredentialBroker{
		listener:    listener,
		server:      server,
		awsToken:    awsToken,
		pulumiToken: pulumiToken,
		uri:         "http://" + listener.Addr().String() + "/v1/credentials",
	}
	go func() {
		_ = server.Serve(listener)
	}()
	return broker, nil
}

func randomBearerToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	encoded := "Bearer " + base64.RawURLEncoding.EncodeToString(value)
	zeroBytes(value)
	return encoded, nil
}

func (broker *localCredentialBroker) close() {
	if broker == nil {
		return
	}
	_ = broker.server.Close()
	_ = broker.listener.Close()
}
