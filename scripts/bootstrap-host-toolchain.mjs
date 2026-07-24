const SHA256 = /^[a-f0-9]{64}$/;

const expectedArchives = Object.freeze({
  go: {
    version: "1.26.5",
    amd64: [
      "go1.26.5.linux-amd64.tar.gz",
      "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053",
    ],
    arm64: [
      "go1.26.5.linux-arm64.tar.gz",
      "fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49",
    ],
  },
  node: {
    version: "24.18.0",
    amd64: [
      "node-v24.18.0-linux-x64.tar.xz",
      "55aa7153f9d88f28d765fcdad5ae6945b5c0f98a36881703817e4c450fa76742",
    ],
    arm64: [
      "node-v24.18.0-linux-arm64.tar.xz",
      "58c9520501f6ae2b52d5b210444e24b9d0c029a58c5011b797bc1fe7105886f6",
    ],
  },
  pulumiAwsProvider: {
    version: "7.27.0",
    amd64: [
      "pulumi-resource-aws-v7.27.0-linux-amd64.tar.gz",
      "6622158479a5f03877933fb26df8bc6c793dd2bbf841527eca699e8e8e62fdbf",
    ],
    arm64: [
      "pulumi-resource-aws-v7.27.0-linux-arm64.tar.gz",
      "43f14692bdd1dcee11e413e90742120a41e353767e795f56cab9fc74951771ed",
    ],
  },
});

export function assertHostToolchainPins(value) {
  if (
    value?.apiVersion !== "security.deus.dev/bootstrap-host-toolchain/v1" ||
    value.awsCli !== "2.36.2" ||
    value.git !== "2.55.0" ||
    value.slsaVerifier !== "2.7.1" ||
    value.awsCliSigningKeyFingerprint !==
      "FB5DB77FD5C118B80511ADA8A6310ACC4672475C" ||
    exactKeys(value) !==
      "apiVersion,awsCli,awsCliSigningKeyFingerprint,git,go,node,pulumi,pulumiAwsProvider,slsaVerifier" ||
    !validArchiveSet(value.go, expectedArchives.go) ||
    !validArchiveSet(value.node, expectedArchives.node) ||
    !validPulumi(value.pulumi) ||
    !validArchiveSet(
      value.pulumiAwsProvider,
      expectedArchives.pulumiAwsProvider,
    )
  ) {
    throw new Error("authenticated bootstrap host toolchain is malformed");
  }
  return value;
}

function validPulumi(value) {
  return (
    value?.version === "3.253.0" &&
    value.releaseTag === "v3.253.0" &&
    value.releaseCommit === "94536e5" &&
    value.artifactVerification === "authenticated-host-kit-pinned-sha256" &&
    exactKeys(value) ===
      "artifactVerification,linuxArchives,releaseCommit,releaseTag,version" &&
    exactArchiveInventory(value.linuxArchives, {
      amd64: [
        "pulumi-v3.253.0-linux-x64.tar.gz",
        "33161e521280e6c77395a46344dba5ff9c118a90df254801e662087143b4d1ac",
      ],
      arm64: [
        "pulumi-v3.253.0-linux-arm64.tar.gz",
        "7d7074d67a76139226c163b2365f14fbd45d8e2251362a2e10dc4602b3b577ea",
      ],
    })
  );
}

function validArchiveSet(value, expected) {
  return (
    value?.version === expected.version &&
    exactKeys(value) === "linuxArchives,version" &&
    exactArchiveInventory(value.linuxArchives, expected)
  );
}

function exactArchiveInventory(value, expected) {
  if (exactKeys(value) !== "amd64,arm64") return false;
  return ["amd64", "arm64"].every((architecture) => {
    const archive = value?.[architecture];
    return (
      exactKeys(archive) === "file,sha256" &&
      archive.file === expected[architecture][0] &&
      archive.sha256 === expected[architecture][1] &&
      SHA256.test(archive.sha256)
    );
  });
}

function exactKeys(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return "";
  }
  return Object.keys(value).sort().join(",");
}
