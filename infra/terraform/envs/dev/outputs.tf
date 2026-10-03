output "api_url" {
  description = "Point a DNS CNAME/alias at this and use https://<your-domain>."
  value       = "https://${module.ecs.alb_dns_name}"
}

output "bucket_name" {
  value = module.s3.bucket_name
}

output "ecr_repository_url" {
  value = module.ecr.repository_url
}

output "ecs_cluster" {
  value = module.ecs.cluster_name
}

output "ecs_service" {
  value = module.ecs.service_name
}

output "task_definition_family" {
  value = module.ecs.task_definition_family
}

output "github_deploy_role_arn" {
  value = try(module.github_oidc[0].deploy_role_arn, null)
}

output "alarm_topic_arn" {
  value = module.observability.alarm_topic_arn
}
