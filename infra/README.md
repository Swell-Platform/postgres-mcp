# Postgres MCP image delivery

This follows IAS's Kafka image pattern: Pulumi owns the ECR repository,
obtains short-lived ECR credentials, and builds/pushes the image. The build
provider is `@pulumi/docker-build` to publish one AMD64/ARM64 manifest.
Pulumi uses the existing central S3 backend and management KMS secrets provider.
No infrastructure-repository checkout is needed by CI or WorkPane.

Two separate projects keep routine image publication out of IAM and repository
management. `postgres-mcp-registry/nonprod` adopts the existing repository and
creates the GitHub OIDC publisher role. `postgres-mcp-image/nonprod` only builds
and pushes images; its role cannot manage IAM or delete the repository/images.

## One-time bootstrap

Nonprod bootstrap was completed on 2026-10-02: the existing ECR repository was
imported, the publisher role/policy created, and both stacks initialized on the
central S3/KMS backend. Select these existing stacks for subsequent updates;
do not rerun `stack init`. No image was pushed during bootstrap. The steps below
document the original adoption procedure.

Run as an authorized nonprod infrastructure operator, after reviewing the code.
The existing GitHub OIDC provider is reused. Both project names are new;
confirm they remain absent before initializing stacks. Never initialize over an
existing stack or switch to an empty backend to avoid an import failure.

```bash
npm ci --prefix infra
export AWS_PROFILE=nonprod
export PULUMI_BACKEND_URL='s3://swell-pulumi-state-195969062870?region=us-west-2&awssdk=v2'
export PULUMI_SECRETS_PROVIDER='awskms:///arn:aws:kms:us-west-2:195969062870:key/db6a398f-c0e3-4180-86c5-227ef790beb0?region=us-west-2'
pulumi login --non-interactive "$PULUMI_BACKEND_URL"
pulumi whoami -v
pulumi stack ls --all
pulumi -C infra/registry stack init organization/postgres-mcp-registry/nonprod \
  --secrets-provider "$PULUMI_SECRETS_PROVIDER"
pulumi -C infra/registry preview --stack organization/postgres-mcp-registry/nonprod --diff
```

The preview must import `docker/library/postgres-mcp` in account `922751599449`,
create only the publisher role and inline policy, and propose no repository
replacement or image deletion. The repository's mutable tags, AES256 encryption,
disabled scanning, and absent lifecycle/repository policies are preserved.
The repository is protected and `forceDelete` is disabled.

After approval, apply adoption and initialize the separate empty image stack:

```bash
pulumi -C infra/registry up --stack organization/postgres-mcp-registry/nonprod
pulumi -C infra/image stack init organization/postgres-mcp-image/nonprod \
  --secrets-provider "$PULUMI_SECRETS_PROVIDER"
```

Commit the resulting stack secrets-provider metadata. It contains no plaintext
credentials. Do not run the registry project from the image publisher workflow.
The publisher role's object access is limited to the image project's state,
history, backups, and locks, plus read access to backend metadata. The central
backend's existing cross-account bucket/KMS policies must permit this nonprod
role; verify the first OIDC run rather than assuming local SSO proves CI access.

The repository is beneath the existing `docker` Docker Hub pull-through-cache
prefix. This change deliberately preserves its name and does not configure an
upstream image or invoke cache refresh/import actions. Our CI identity has no
`ecr:CreateRepository` or `ecr:BatchImportUpstreamImage` permission. A future move
to a dedicated prefix needs a coordinated consumer migration.

## Automatic delivery

For a local preview, no revision setting is needed:

```bash
AWS_PROFILE=nonprod pulumi -C infra/image preview \
  --stack organization/postgres-mcp-image/nonprod
```

Previews use the checkout's current HEAD when `revision` is absent and never
build or push. Actual updates require an explicit full commit SHA, supplied by
CI as `postgres-mcp-image:revision`. A preview on an uncommitted checkout is a
resource plan, not evidence that those changes have been built or released.

`.github/workflows/build.yml` runs lint, Python and Pulumi type checks, and tests
only on pull requests. After merge, `publish-ecr.yml` independently builds and
publishes on `main` pushes, without rerunning pytest or the container MCP test.
The publication workflow can also be dispatched on `main` to retry a failed run.
Require the PR's `postgres-mcp-ci` check in branch protection to gate merging;
direct pushes to main also trigger publication without a PR test run.
PRs and other branches cannot assume the publisher role or publish images.
No Docker Hub credentials, long-lived AWS keys, or Pulumi Cloud token are used.

During PR validation, CI builds a native-platform container and exercises it via MCP
against an isolated disposable PostgreSQL instance: tool registration, ANALYZE,
read-only execution, mutation rejection, and Presidio redaction. No database
credentials or customer data are used.

Pulumi builds with `INSTALL_PRESIDIO=true`. The Dockerfile verifies Presidio and
the English NLP model as the runtime user before completing either platform's
build. Builds do not execute database queries. Previews do not build or push.
Publication is serialized and is not cancelled mid-update.

The image is pushed to:

```text
922751599449.dkr.ecr.us-west-2.amazonaws.com/docker/library/postgres-mcp:<full-commit-SHA>
922751599449.dkr.ecr.us-west-2.amazonaws.com/docker/library/postgres-mcp:latest
```

The job summary records the exact digest reference (`...@sha256:...`), which is
the preferred WorkPane configuration. Version tags are commit-specific by
convention; ECR remains mutable to preserve the existing `latest` behavior.
Retain old images for rollback; no lifecycle cleanup is added in this change.

Publishing makes the image available; it does not restart WorkPane, deploy a
database-side service, or alter database permissions. WorkPane controls when to
pull and switch each environment. Roll back by selecting a previous digest and
restarting that environment. Validate using `SELECT 1` and guarded
`explain_query(sql="SELECT 1", analyze=true)` calls.
