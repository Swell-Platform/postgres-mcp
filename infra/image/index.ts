import * as aws from "@pulumi/aws";
import * as docker from "@pulumi/docker-build";
import * as pulumi from "@pulumi/pulumi";
import { execFileSync } from "node:child_process";
import * as path from "node:path";

const root = path.resolve(__dirname, "../..");
const config = new pulumi.Config();
// A plain local preview needs no saved release revision. Updates still require
// CI/operator input so a checkout's HEAD cannot silently label a release.
const revision = config.get("revision") ?? (pulumi.runtime.isDryRun()
  ? execFileSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8" }).trim()
  : config.require("revision"));
if (!/^[a-f0-9]{40}$/.test(revision)) {
  throw new Error("revision must be the full Git commit SHA being built");
}
const repository = aws.ecr.getRepositoryOutput({ name: "docker/library/postgres-mcp" });
const authorization = aws.ecr.getAuthorizationTokenOutput({ registryId: repository.registryId });
const image = new docker.Image("postgres-mcp", {
  context: { location: root },
  dockerfile: { location: path.join(root, "Dockerfile") },
  platforms: ["linux/amd64", "linux/arm64"],
  buildArgs: { INSTALL_PRESIDIO: "true", GIT_REVISION: revision },
  tags: [
    pulumi.interpolate`${repository.repositoryUrl}:${revision}`,
    pulumi.interpolate`${repository.repositoryUrl}:latest`,
  ],
  registries: [{
    address: authorization.proxyEndpoint,
    username: authorization.userName,
    password: pulumi.secret(authorization.password),
  }],
  push: true,
  buildOnPreview: false,
}, { retainOnDelete: true });

export const imageTag = pulumi.interpolate`${repository.repositoryUrl}:${revision}`;
// A content digest is public metadata; never propagate registry-token secrecy
// into the reference displayed in CI and copied into WorkPane.
export const imageDigest = pulumi.unsecret(image.digest);
export const imageRef = pulumi.interpolate`${repository.repositoryUrl}@${imageDigest}`;
