data "aws_iam_policy_document" "circleci_assume_role" {
  statement {
    sid     = "CircleCIOrganizationOIDC"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.circleci.arn]
    }

    # Organization-only trust, as requested. Every project in this CircleCI
    # organization can assume the role if it obtains a valid token.
    condition {
      test     = "StringEquals"
      variable = "${local.circleci_claim_namespace}:aud"
      values   = [var.circleci_org_id]
    }
  }
}

resource "aws_iam_role" "circleci" {
  name                 = var.role_name
  description          = "CircleCI OIDC role for publishing OSSEC Debian packages"
  assume_role_policy   = data.aws_iam_policy_document.circleci_assume_role.json
  max_session_duration = 3600
  tags                 = var.tags
}

data "aws_iam_policy_document" "s3_upload" {
  statement {
    sid    = "GetArtifactBucketLocation"
    effect = "Allow"
    actions = [
      "s3:GetBucketLocation"
    ]
    resources = ["arn:aws:s3:::${var.artifact_bucket}"]
  }

  statement {
    sid    = "ListArtifactPrefix"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads"
    ]
    resources = ["arn:aws:s3:::${var.artifact_bucket}"]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        local.normalized_artifact_prefix,
        "${local.normalized_artifact_prefix}/*"
      ]
    }
  }

  statement {
    sid    = "WriteArtifactObjects"
    effect = "Allow"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:ListMultipartUploadParts",
      "s3:PutObject"
    ]
    resources = [local.artifact_object_arn]
  }
}

resource "aws_iam_role_policy" "s3_upload" {
  name   = "OSSECInstallerArtifactUpload"
  role   = aws_iam_role.circleci.id
  policy = data.aws_iam_policy_document.s3_upload.json
}
