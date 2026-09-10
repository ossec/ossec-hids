locals {
  normalized_artifact_prefix = trim(var.artifact_prefix, "/")
  circleci_issuer            = "https://oidc.circleci.com/org/${var.circleci_org_id}"
  circleci_claim_namespace   = "oidc.circleci.com/org/${var.circleci_org_id}"
  artifact_object_arn        = "arn:aws:s3:::${var.artifact_bucket}/${local.normalized_artifact_prefix}/*"
}
