# CircleCI OSSEC publisher role

Terraform configuration for the CircleCI OIDC role that publishes OSSEC Debian
packages to:

```text
s3://td-ossec-agents/installer/
```

The AWS account is restricted by the provider configuration to account
`113345163213`.

## What this creates

- A CircleCI organization-specific IAM OIDC provider.
- IAM role `CircleCI-OSSEC-Packages-Publisher`.
- An inline policy that permits package uploads only under:

  ```text
  s3://td-ossec-agents/installer/*
  ```

The role cannot delete objects and has no access to objects outside the
`installer/` prefix.

The trust policy is organization-wide because the current requirement selected
organization-only trust. Any project in the CircleCI organization can assume
this role with a valid CircleCI OIDC token. Restricting the role to a specific
CircleCI project is recommended for production.

## Prerequisites

The operator running Terraform needs AWS credentials with permission to manage:

- `iam:CreateOpenIDConnectProvider`
- `iam:CreateRole`
- `iam:PutRolePolicy`
- `iam:TagOpenIDConnectProvider`
- `iam:TagRole`

The CircleCI organization ID is required. It is used in all three places:

1. The OIDC issuer URL: `https://oidc.circleci.com/org/<org-id>`
2. The OIDC provider audience/client ID.
3. The IAM trust-policy `aud` condition.

## Apply

From this directory:

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with the real CircleCI organization ID and S3 region.

terraform init
terraform fmt -recursive
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

Use an AWS profile explicitly when appropriate:

```bash
AWS_PROFILE=<profile> terraform plan
AWS_PROFILE=<profile> terraform apply tfplan
```

The account guard in `versions.tf` prevents Terraform from applying to an AWS
account other than `113345163213`.

## CircleCI context values

After applying, configure the `ossec-package-publisher` context with:

```text
AWS_ROLE_ARN = <terraform output -raw role_arn>
AWS_REGION   = <region of td-ossec-agents>
S3_BUCKET    = td-ossec-agents
S3_PREFIX    = installer
```

Do not configure long-lived AWS access keys. The CircleCI `aws-cli` orb in the
main pipeline assumes this role through OIDC.

## Existing OIDC provider

If the CircleCI OIDC provider already exists in account `113345163213`, do not
apply this configuration unchanged. Import the existing provider into the
Terraform state, or adapt the module to reference the existing provider, to
avoid an `EntityAlreadyExists` error.

## Safer project restriction

To restrict this role to one CircleCI project, add a second trust-policy
condition using the documented claim namespace:

```hcl
condition {
  test     = "StringEquals"
  variable = "${local.circleci_claim_namespace}:oidc.circleci.com/project-id"
  values   = [var.circleci_project_id]
}
```

That requires adding a `circleci_project_id` variable and is preferable once
the CircleCI project UUID is available.
