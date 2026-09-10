resource "aws_iam_openid_connect_provider" "circleci" {
  url            = local.circleci_issuer
  client_id_list = [var.circleci_org_id]
  tags           = var.tags
}
