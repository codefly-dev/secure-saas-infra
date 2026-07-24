package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestChildEnvironmentIsAllowlistedAndFixed(t *testing.T) {
	inherited, err := environmentMap([]string{
		"AWS_ACCESS_KEY_ID=ASIA1234567890123456",
		"AWS_SECRET_ACCESS_KEY=secret",
		"AWS_SESSION_TOKEN=token",
		"AWS_REGION=us-east-1",
		"PULUMI_HOME=/tmp/attacker",
		"PATH=/tmp/attacker",
		"NODE_OPTIONS=--require=/tmp/attacker.js",
		"LD_PRELOAD=/tmp/attacker.so",
		"DYLD_INSERT_LIBRARIES=/tmp/attacker.dylib",
		"HTTPS_PROXY=https://attacker.invalid",
		"TMPDIR=/tmp/attacker",
		"HOME=/root",
		"USER=attacker",
		"LOGNAME=attacker",
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := &localCredentialBroker{
		awsToken: "Bearer 1234567890123456789012345678901234567890123",
		uri:      "http://127.0.0.1:45678/v1/credentials",
	}
	actual := buildChildEnvironment(inherited, "/tmp/isolated", "/tmp/isolated/tmp", "bootstrap", broker)
	for _, forbidden := range []string{
		"AWS_ACCESS_KEY_ID=",
		"AWS_SECRET_ACCESS_KEY=",
		"AWS_SESSION_TOKEN=",
		"NODE_OPTIONS=",
		"LD_PRELOAD=",
		"DYLD_INSERT_LIBRARIES=",
		"HTTPS_PROXY=",
		"PULUMI_HOME=/tmp/attacker",
		"PATH=/tmp/attacker",
		"TMPDIR=/tmp/attacker",
		"HOME=/root",
		"USER=attacker",
		"LOGNAME=attacker",
	} {
		if slices.ContainsFunc(actual, func(value string) bool { return strings.HasPrefix(value, forbidden) }) {
			t.Fatalf("unsafe inherited entry survived: %s", forbidden)
		}
	}
	for _, required := range []string{
		"AWS_CONFIG_FILE=/dev/null",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN=" + broker.awsToken,
		"AWS_CONTAINER_CREDENTIALS_FULL_URI=" + broker.uri,
		"AWS_EC2_METADATA_DISABLED=true",
		"AWS_SHARED_CREDENTIALS_FILE=/dev/null",
		"HOME=/tmp/isolated",
		"PATH=" + installRoot + "/bin",
		"PULUMI_HOME=" + pulumiHome,
		"PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION=true",
		"PULUMI_IGNORE_AMBIENT_PLUGINS=true",
		"TMPDIR=/tmp/isolated/tmp",
		"DEUS_QUALIFIED_EXECUTION_ROOT=" + executionRoot,
		"DEUS_EXECUTION_CONFINEMENT=systemd-noexec-landlock-v1",
		"DEUS_PULUMI_BROKER_FD=3",
	} {
		if !slices.Contains(actual, required) {
			t.Fatalf("missing fixed entry %s", required)
		}
	}
	pathEntry := "PATH=" + installRoot + "/bin"
	if !slices.Contains(actual, pathEntry) || strings.Contains(pathEntry, "/usr/bin") || strings.Contains(pathEntry, ":/bin") {
		t.Fatal("credentialed launcher PATH exposes host executables")
	}
}

func TestQualificationToolingIsIrreversiblyRetiredBeforeCredentials(t *testing.T) {
	root := t.TempDir()
	paths := []string{
		filepath.Join(root, "qualification"),
		filepath.Join(root, "qualification-bin"),
		filepath.Join(root, "toolchains", "go"),
	}
	for _, value := range paths {
		if err := os.MkdirAll(value, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(value, "host-tool"), []byte("tool"), 0o555); err != nil {
			t.Fatal(err)
		}
	}
	if err := requireQualificationToolingRetired(paths); err == nil {
		t.Fatal("installed qualification tooling was accepted on a credential host")
	}
	if err := retireQualificationTooling(paths); err != nil {
		t.Fatal(err)
	}
	if err := requireQualificationToolingRetired(paths); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialBrokerRequiresAuthorizationAndReturnsTemporarySession(t *testing.T) {
	session := credentialEnvelope{
		Version:                1,
		AccessKeyID:            "ASIA1234567890123456",
		SecretAccessKey:        "secret-secret-secret",
		SessionToken:           "session-token-session-token",
		Expiration:             time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		PulumiAccessToken:      "pulumi-access-token-value",
		PulumiConfigPassphrase: "passphrase",
	}
	broker, err := startCredentialBroker(session)
	if err != nil {
		t.Fatal(err)
	}
	defer broker.close()
	for index := 0; index < 300; index++ {
		if response, err := http.Get(broker.uri); err != nil {
			t.Fatal(err)
		} else {
			_ = response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("unauthorized broker request returned %d", response.StatusCode)
			}
		}
	}
	request, err := http.NewRequest(http.MethodGet, broker.uri, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", broker.awsToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK ||
		strings.Contains(string(contents), session.PulumiAccessToken) ||
		!strings.Contains(string(contents), session.AccessKeyID) {
		t.Fatalf("unexpected credential broker response: %d %s %v", response.StatusCode, contents, err)
	}
	for _, attempt := range []struct {
		path  string
		token string
	}{
		{"/v1/pulumi", broker.awsToken},
		{"/v1/credentials", broker.pulumiToken},
	} {
		crossRequest, requestErr := http.NewRequest(http.MethodGet, strings.Replace(broker.uri, "/v1/credentials", attempt.path, 1), nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		crossRequest.Header.Set("Authorization", attempt.token)
		crossResponse, requestErr := http.DefaultClient.Do(crossRequest)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		_ = crossResponse.Body.Close()
		if crossResponse.StatusCode != http.StatusForbidden {
			t.Fatalf("cross-capability broker request returned %d", crossResponse.StatusCode)
		}
	}
	pulumiRequest, err := http.NewRequest(http.MethodGet, strings.Replace(broker.uri, "/v1/credentials", "/v1/pulumi", 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	pulumiRequest.Header.Set("Authorization", broker.pulumiToken)
	pulumiResponse, err := http.DefaultClient.Do(pulumiRequest)
	if err != nil {
		t.Fatal(err)
	}
	pulumiContents, err := io.ReadAll(pulumiResponse.Body)
	_ = pulumiResponse.Body.Close()
	if err != nil || pulumiResponse.StatusCode != http.StatusOK || !strings.Contains(string(pulumiContents), session.PulumiAccessToken) {
		t.Fatalf("unexpected Pulumi broker response: %d %s %v", pulumiResponse.StatusCode, pulumiContents, err)
	}
}

func TestNonPulumiModesDoNotReceivePulumiSecrets(t *testing.T) {
	inherited := map[string]string{
		"AWS_ACCESS_KEY_ID":             "ASIA1234567890123456",
		"AWS_SECRET_ACCESS_KEY":         "secret",
		"AWS_SESSION_TOKEN":             "token",
		"PULUMI_ACCESS_TOKEN":           "pulumi-secret",
		"PULUMI_CONFIG_PASSPHRASE":      "passphrase",
		"PULUMI_CONFIG_PASSPHRASE_FILE": "/tmp/passphrase",
	}
	broker := &localCredentialBroker{
		awsToken: "Bearer 1234567890123456789012345678901234567890123",
		uri:      "http://127.0.0.1:45678/v1/credentials",
	}
	for _, mode := range []string{"access-provisioner", "organization-recovery"} {
		actual := buildChildEnvironment(inherited, "/tmp/isolated", "/tmp/isolated/tmp", mode, broker)
		for _, entry := range actual {
			if strings.HasPrefix(entry, "PULUMI_ACCESS_TOKEN=") || strings.HasPrefix(entry, "PULUMI_CONFIG_PASSPHRASE") || strings.HasPrefix(entry, "DEUS_PULUMI_BROKER_FD=") {
				t.Fatalf("%s received Pulumi secret or capability: %s", mode, entry)
			}
		}
	}
}

func TestSealedCopyUsesNewInodesAndIgnoresOldWritableDescriptors(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "sealed")
	defer func() { _ = os.Chmod(destination, 0o700) }()
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(source, "bootstrap.mjs")
	if err := os.WriteFile(file, []byte("qualified"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("bootstrap.mjs", filepath.Join(source, "entrypoint")); err != nil {
		t.Fatal(err)
	}
	oldDescriptor, err := os.OpenFile(file, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer oldDescriptor.Close()
	if err := copySealedTree(source, destination, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if _, err := oldDescriptor.WriteAt([]byte("attacker!"), 0); err != nil {
		t.Fatal(err)
	}
	sealed, err := os.ReadFile(filepath.Join(destination, "bootstrap.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	if string(sealed) != "qualified" {
		t.Fatalf("old writable descriptor changed sealed inode: %q", sealed)
	}
	link, err := os.Readlink(filepath.Join(destination, "entrypoint"))
	if err != nil || link != "bootstrap.mjs" {
		t.Fatalf("sealed symlink changed: %q, %v", link, err)
	}
	info, err := os.Stat(filepath.Join(destination, "bootstrap.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o550 {
		t.Fatalf("sealed executable mode is %v", info.Mode().Perm())
	}
}

func TestSealedCopyRejectsConfidentialSigningReviewBundle(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "sealed")
	if err := os.MkdirAll(filepath.Join(source, "artifacts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "artifacts", "bootstrap-signing-review-bundle.json"), []byte("confidential"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copySealedTree(source, destination, os.Getuid(), os.Getgid()); err == nil || !strings.Contains(err.Error(), "confidential transient") {
		t.Fatalf("confidential review bundle was copied into the sealed tree: %v", err)
	}
}

func TestSealedCopyRejectsSymlinksOutsideExecutionRoot(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "sealed")
	defer func() { _ = os.Chmod(destination, 0o700) }()
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "outside-secret")
	if err := os.WriteFile(secret, []byte("must-not-copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(source, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := copySealedTree(source, destination, os.Getuid(), os.Getgid()); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("external snapshot symlink was accepted: %v", err)
	}
}

func TestLauncherBindingRejectsStaleInstalledBinary(t *testing.T) {
	root := t.TempDir()
	installed := filepath.Join(root, "installed")
	snapshot := filepath.Join(root, "snapshot")
	candidate := filepath.Join(root, "candidate.json")
	trustPath := filepath.Join(root, "trust.json")
	node := filepath.Join(root, "node")
	trusted := []byte("current-launcher")
	if err := os.WriteFile(installed, trusted, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshot, trusted, 0o500); err != nil {
		t.Fatal(err)
	}
	nodeBytes := []byte("trusted-node")
	if err := os.WriteFile(node, nodeBytes, 0o500); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(trusted))
	nodeDigest := fmt.Sprintf("%x", sha256.Sum256(nodeBytes))
	trustDigest := writeSignedLauncherCandidate(t, candidate, trustPath, digest, node, nodeDigest)
	if err := verifyLauncherBinding(candidate, installed, snapshot, trustPath, trustDigest, node); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(installed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed, []byte("stale-launcher"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := verifyLauncherBinding(candidate, installed, snapshot, trustPath, trustDigest, node); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale installed launcher was accepted: %v", err)
	}
}

func TestLauncherBindingRejectsCandidateTampering(t *testing.T) {
	root := t.TempDir()
	installed := filepath.Join(root, "installed")
	snapshot := filepath.Join(root, "snapshot")
	candidate := filepath.Join(root, "candidate.json")
	trustPath := filepath.Join(root, "trust.json")
	node := filepath.Join(root, "node")
	launcher := []byte("current-launcher")
	if err := os.WriteFile(installed, launcher, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshot, launcher, 0o500); err != nil {
		t.Fatal(err)
	}
	nodeBytes := []byte("trusted-node")
	if err := os.WriteFile(node, nodeBytes, 0o500); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(launcher))
	nodeDigest := fmt.Sprintf("%x", sha256.Sum256(nodeBytes))
	trustDigest := writeSignedLauncherCandidate(t, candidate, trustPath, digest, node, nodeDigest)
	contents, err := os.ReadFile(candidate)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(contents), digest, strings.Repeat("a", 64), 1)
	if err := os.Chmod(candidate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, []byte(tampered), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := verifyLauncherBinding(candidate, installed, snapshot, trustPath, trustDigest, node); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tampered signed candidate was accepted: %v", err)
	}
}

func TestCanonicalJSONAcceptsOnlyMinimalSafeNonnegativeIntegers(t *testing.T) {
	accepted, err := decodeJSONObject([]byte(`{"entryCount":300000,"maximumFileSize":2147483648,"totalFileBytes":8589934592}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := canonicalJSON(accepted)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"entryCount":300000,"maximumFileSize":2147483648,"totalFileBytes":8589934592}` {
		t.Fatalf("unexpected canonical safe integers: %s", encoded)
	}
	for _, document := range []string{
		`{"value":-1}`,
		`{"value":1.5}`,
		`{"value":1e3}`,
		`{"value":9007199254740992}`,
	} {
		decoded, err := decodeJSONObject([]byte(document))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := canonicalJSON(decoded); err == nil {
			t.Fatalf("unsafe canonical number was accepted: %s", document)
		}
	}
}

func writeSignedLauncherCandidate(t *testing.T, candidatePath, trustPath, launcherDigest, installedNodePath, nodeDigest string) string {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID := fmt.Sprintf("%x", sha256.Sum256(publicDER))
	trust := map[string]any{
		"algorithm":     "Ed25519",
		"apiVersion":    "security.deus.dev/bootstrap-qualification-trust/v1",
		"configured":    true,
		"keyId":         keyID,
		"publicKeySpki": base64.RawURLEncoding.EncodeToString(publicDER),
	}
	trustContents, err := json.Marshal(trust)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustPath, trustContents, 0o400); err != nil {
		t.Fatal(err)
	}
	subject := map[string]any{
		"apiVersion":   "security.deus.dev/bootstrap-candidate/v1",
		"generatedAt":  time.Now().UTC().Format(time.RFC3339Nano),
		"signingKeyId": keyID,
		"nativeLauncher": map[string]any{
			"path":   "artifacts/deus-aws-bootstrap",
			"sha256": launcherDigest,
		},
		"runtime": map[string]any{
			"executables": []any{
				map[string]any{
					"name":     "node",
					"path":     installedNodePath,
					"realPath": installedNodePath,
					"sha256":   nodeDigest,
				},
			},
		},
		"sealInventory": map[string]any{
			"path":            "artifacts/bootstrap-seal-inventory.json",
			"sha256":          strings.Repeat("e", 64),
			"entryCount":      json.Number("300000"),
			"totalFileBytes":  json.Number("8589934592"),
			"maximumFileSize": json.Number("2147483648"),
		},
	}
	canonical, err := canonicalJSON(subject)
	if err != nil {
		t.Fatal(err)
	}
	candidateDigest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	signature := ed25519.Sign(privateKey, []byte("security.deus.dev/bootstrap-candidate/v1:"+candidateDigest))
	candidate := map[string]any{}
	for key, value := range subject {
		candidate[key] = value
	}
	candidate["candidateDigest"] = candidateDigest
	candidate["signature"] = map[string]any{
		"algorithm": "Ed25519",
		"keyId":     keyID,
		"value":     base64.RawURLEncoding.EncodeToString(signature),
	}
	candidateContents, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidatePath, candidateContents, 0o400); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(trustContents))
}

func TestCredentialEnvelopeMustBePipedTemporaryAndEntrypointScoped(t *testing.T) {
	now := time.Now().UTC()
	valid := fmt.Sprintf(`{"Version":1,"AccessKeyId":"ASIA1234567890123456","SecretAccessKey":"secret-secret-secret","SessionToken":"session-token-session-token","Expiration":%q,"PulumiAccessToken":"pulumi-access-token-value"}`, now.Add(time.Hour).Format(time.RFC3339))
	if _, err := readCredentialEnvelope(strings.NewReader(valid), "bootstrap", now); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{
		strings.Replace(valid, "ASIA", "AKIA", 1),
		strings.Replace(valid, "pulumi-access-token-value", "short", 1),
		strings.Replace(valid, `"Version":1`, `"Version":1,"Unexpected":true`, 1),
		strings.Replace(
			valid,
			now.Add(time.Hour).Format(time.RFC3339),
			now.Add(66*time.Minute).Format(time.RFC3339),
			1,
		),
	} {
		if _, err := readCredentialEnvelope(strings.NewReader(mutation), "bootstrap", now); err == nil {
			t.Fatal("unsafe credential envelope mutation was accepted")
		}
	}
	if _, err := readCredentialEnvelope(strings.NewReader(valid), "access-provisioner", now); err == nil {
		t.Fatal("access provisioner accepted Pulumi credentials")
	}
	if _, err := readCredentialEnvelope(strings.NewReader(valid), "organization-recovery", now); err == nil {
		t.Fatal("organization recovery accepted Pulumi credentials")
	}
	if err := rejectInheritedCredentialMaterial([]string{"AWS_ACCESS_KEY_ID=ASIA1234567890123456"}); err == nil {
		t.Fatal("raw inherited AWS credentials were accepted")
	}
	filtered, fd, err := extractCredentialFD([]string{"bootstrap", "--credential-fd", "7", "--preview"})
	if err != nil || fd != 7 || !slices.Equal(filtered, []string{"bootstrap", "--preview"}) {
		t.Fatalf("credential FD extraction failed: %v %d %v", err, fd, filtered)
	}
	options, err := parseCredentialEnvelopeArgs([]string{
		"--mode", "bootstrap", "--aws-fd", "4", "--pulumi-token-fd", "5",
	})
	if err != nil || options.mode != "bootstrap" || options.awsFD != 4 || options.pulumiTokenFD != 5 {
		t.Fatalf("credential-envelope arguments failed: %#v %v", options, err)
	}
	if _, err := parseCredentialEnvelopeArgs([]string{
		"--mode", "bootstrap", "--aws-fd", "4", "--pulumi-token-fd", "4",
	}); err == nil {
		t.Fatal("credential-envelope accepted duplicate descriptors")
	}
	recovery, err := parseCredentialEnvelopeArgs([]string{
		"--mode", "organization-recovery", "--aws-fd", "4",
	})
	if err != nil || recovery.mode != "organization-recovery" || recovery.awsFD != 4 || recovery.pulumiTokenFD != -1 {
		t.Fatalf("organization recovery credential-envelope arguments failed: %#v %v", recovery, err)
	}
	if _, err := parseCredentialEnvelopeArgs([]string{
		"--mode", "organization-recovery", "--aws-fd", "4", "--pulumi-token-fd", "5",
	}); err == nil {
		t.Fatal("organization recovery credential-envelope accepted a Pulumi descriptor")
	}
}

func TestRuntimeIdentityMustMatchDistinctSealedAccount(t *testing.T) {
	if err := validateRuntimeIdentity([]byte("1001:1002\n"), 1001, 1002); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		contents []byte
		uid      int
		gid      int
	}{
		{[]byte("1001:1002\n"), 1003, 1002},
		{[]byte("1001:1002\n"), 1001, 1003},
		{[]byte("0:1002\n"), 0, 1002},
		{[]byte("1001:1002"), 1001, 1002},
	} {
		if err := validateRuntimeIdentity(test.contents, test.uid, test.gid); err == nil {
			t.Fatalf("unsafe runtime identity was accepted: %q", test.contents)
		}
	}
}

func TestCredentialedRootOverrideIsRejectedBeforeFilesystemAccess(t *testing.T) {
	err := run(
		[]string{"bootstrap", "--root", "/tmp/attacker"},
		[]string{
			"AWS_ACCESS_KEY_ID=ASIA1234567890123456",
			"AWS_SECRET_ACCESS_KEY=secret",
			"AWS_SESSION_TOKEN=token",
		},
		nil,
		nil,
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "cannot be overridden") {
		t.Fatalf("unexpected result: %v", err)
	}
}
