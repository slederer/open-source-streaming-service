output "ec2_public_ip" {
  description = "Public IP of the EC2 instance"
  value       = aws_eip.app.public_ip
}

output "ec2_instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.app.id
}

output "s3_input_bucket" {
  description = "S3 bucket for video masters"
  value       = aws_s3_bucket.input.bucket
}

output "s3_output_bucket" {
  description = "S3 bucket for encoded output"
  value       = aws_s3_bucket.output.bucket
}

output "s3_thumbnails_bucket" {
  description = "S3 bucket for thumbnails"
  value       = aws_s3_bucket.thumbnails.bucket
}

output "cloudfront_domain" {
  description = "CloudFront distribution domain name"
  value       = aws_cloudfront_distribution.cdn.domain_name
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = aws_cloudfront_distribution.cdn.id
}

# MediaTailor outputs will be available after running setup-mediatailor.sh
