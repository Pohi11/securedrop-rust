output "log_group_name" {
  value = aws_cloudwatch_log_group.api.name
}

output "log_group_arn" {
  value = aws_cloudwatch_log_group.api.arn
}

output "alarm_topic_arn" {
  value = aws_sns_topic.alarms.arn
}
