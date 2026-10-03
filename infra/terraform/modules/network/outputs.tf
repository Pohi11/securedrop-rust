output "vpc_id" {
  value = aws_vpc.this.id
}

output "vpc_cidr" {
  value = aws_vpc.this.cidr_block
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "app_subnet_ids" {
  value = aws_subnet.app[*].id
}

output "data_subnet_ids" {
  value = aws_subnet.data[*].id
}

output "s3_endpoint_id" {
  value = aws_vpc_endpoint.s3.id
}

output "s3_prefix_list_id" {
  description = "Managed prefix list of S3 public IP ranges, routed through the gateway endpoint."
  value       = aws_vpc_endpoint.s3.prefix_list_id
}
