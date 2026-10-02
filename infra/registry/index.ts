import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";

// Preserve the existing repository and images. Adoption is a one-time operator update.
const repository = new aws.ecr.Repository("postgres-mcp", {
  name: "docker/library/postgres-mcp",
  imageTagMutability: "MUTABLE",
  encryptionConfigurations: [{ encryptionType: "AES256" }],
  imageScanningConfiguration: { scanOnPush: false },
  forceDelete: false,
}, { import: "docker/library/postgres-mcp", protect: true });

const publisher = new aws.iam.Role("postgres-mcp-image-publisher", {
  name: "postgres-mcp-image-publisher",
  assumeRolePolicy: JSON.stringify({
    Version: "2012-10-17",
    Statement: [{
      Effect: "Allow",
      Principal: { Federated: "arn:aws:iam::922751599449:oidc-provider/token.actions.githubusercontent.com" },
      Action: "sts:AssumeRoleWithWebIdentity",
      Condition: { StringEquals: {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:Swell-Platform/postgres-mcp:ref:refs/heads/main",
      } },
    }],
  }),
});

new aws.iam.RolePolicy("postgres-mcp-image-publisher", {
  role: publisher.name,
  policy: repository.arn.apply(arn => JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      { Effect: "Allow", Action: "ecr:GetAuthorizationToken", Resource: "*" },
      { Effect: "Allow", Action: [
        "ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability",
        "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage",
      ], Resource: arn },
      { Effect: "Allow", Action: ["s3:ListBucket", "s3:GetBucketVersioning"],
        Resource: "arn:aws:s3:::swell-pulumi-state-195969062870" },
      { Effect: "Allow", Action: ["s3:GetObject", "s3:GetObjectVersion"],
        Resource: "arn:aws:s3:::swell-pulumi-state-195969062870/.pulumi/meta.yaml" },
      { Effect: "Allow", Action: ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject"],
        Resource: ["stacks", "locks", "history", "backups"].map(directory =>
          `arn:aws:s3:::swell-pulumi-state-195969062870/.pulumi/${directory}/postgres-mcp-image/*`) },
      { Effect: "Allow", Action: ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"],
        Resource: "arn:aws:kms:us-west-2:195969062870:key/db6a398f-c0e3-4180-86c5-227ef790beb0" },
    ],
  })),
});

export const repositoryUrl = repository.repositoryUrl;
export const publisherRoleArn = publisher.arn;
