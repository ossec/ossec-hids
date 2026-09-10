output "role_name" {
  description = "IAM role name for CircleCI package publishing."
  value       = aws_iam_role.circleci.name
}

output "role_arn" {
  description = "Set this as AWS_ROLE_ARN in the CircleCI context."
  value       = aws_iam_role.circleci.arn
}

output "oidc_provider_arn" {
  description = "CircleCI IAM OIDC provider ARN."
  value       = aws_iam_openid_connect_provider.circleci.arn
}

output "artifact_prefix" {
  description = "S3 prefix writable by the role."
  value       = "s3://${var.artifact_bucket}/${local.normalized_artifact_prefix}/"
}
