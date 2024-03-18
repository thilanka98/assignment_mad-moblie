resource "aws_security_group" "webSg" {
  name = "web"

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Web-sg"
  }
}

resource "aws_cloudwatch_log_group" "ec2_logs-ec2-1" {
  name              = "my-ec2-logs"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "ec2_logs-ec2-2" {
  name              = "my-ec2-logs-2"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "ec2_logs-ec2-3" {
  name              = "my-ec2-logs-3"
  retention_in_days = 7
}

resource "aws_iam_role" "ec2_role" {
  name = "ec2_role"

  assume_role_policy = jsonencode({
    "Version"   : "2012-10-17",
    "Statement" : [
      {
        "Effect"    : "Allow",
        "Principal" : {
          "Service" : "ec2.amazonaws.com"
        },
        "Action"    : "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "admin_access_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_policy" "cloudwatch_logs_policy_1" {
  name = "cloudwatch_logs_policy_1"

  policy = jsonencode({
    "Version"   : "2012-10-17",
    "Statement" : [
      {
        "Effect"   : "Allow",
        "Action"   : ["logs:PutLogEvents"],
        "Resource" : ["${aws_cloudwatch_log_group.ec2_logs-ec2-1.arn}:*"]
      }
    ]
  })
}

resource "aws_iam_policy" "cloudwatch_logs_policy_2" {
  name = "cloudwatch_logs_policy_2"

  policy = jsonencode({
    "Version"   : "2012-10-17",
    "Statement" : [
      {
        "Effect"   : "Allow",
        "Action"   : ["logs:PutLogEvents"],
        "Resource" : ["${aws_cloudwatch_log_group.ec2_logs-ec2-2.arn}:*"]
      }
    ]
  })
}

resource "aws_iam_policy" "cloudwatch_logs_policy_3" {
  name = "cloudwatch_logs_policy_3"

  policy = jsonencode({
    "Version"   : "2012-10-17",
    "Statement" : [
      {
        "Effect"   : "Allow",
        "Action"   : ["logs:PutLogEvents"],
        "Resource" : ["${aws_cloudwatch_log_group.ec2_logs-ec2-3.arn}:*"]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudwatch_logs_attachment_1" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.cloudwatch_logs_policy_1.arn
}

resource "aws_iam_role_policy_attachment" "cloudwatch_logs_attachment_2" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.cloudwatch_logs_policy_2.arn
}

resource "aws_iam_role_policy_attachment" "cloudwatch_logs_attachment_3" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.cloudwatch_logs_policy_3.arn
}


resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2_instance_profile"
  role = aws_iam_role.ec2_role.name
}

# EC2 Instances
resource "aws_instance" "ec2-1" {
  ami                    = var.ami_value
  instance_type          = var.instance_type_value
  key_name               = var.key_name
  monitoring             = true
  vpc_security_group_ids = [aws_security_group.webSg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_instance_profile.name
   tags = {
    Name = "ec2-1"
  }

  user_data = <<-EOF
    #!/bin/bash

    sudo yum update -y
    sudo yum install amazon-cloudwatch-agent -y
    sudo dnf install rsyslog -y
    sudo systemctl enable rsyslog --now
    sudo tee /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF_CONFIG'
    {
      "logs": {
        "logs_collected": {
          "files": {
            "collect_list": [
              {
                "file_path": "/var/log/messages",
                "log_group_name": "${aws_cloudwatch_log_group.ec2_logs-ec2-1.name}",
                "log_stream_name": "user-data-errors"
              }
            ]
          }
        }
      },
      "metrics": {
        "append_dimensions": {
          "InstanceId": "$${aws:InstanceId}"
        },
        "metrics_collected": {
          "mem": {
            "measurement": [
              "mem_used_percent"
            ],
            "metrics_collection_interval": 60,
            "resources": [
              "*"
            ]
          },
           "disk": {
            "measurement": [
              "disk_used_percent"
            ],
            "metrics_collection_interval": 60,
            "resources": [
              "/"
            ]
          }
        }
      }
    }
    EOF_CONFIG

    sudo systemctl enable amazon-cloudwatch-agent
    sudo systemctl start amazon-cloudwatch-agent
EOF
}

resource "aws_instance" "ec2-2" {
  ami                    = var.ami_value
  instance_type          = var.instance_type_value
  key_name               = var.key_name
  monitoring             = true
  vpc_security_group_ids = [aws_security_group.webSg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_instance_profile.name
   tags = {
    Name = "ec2-2"
  }


  user_data = <<-EOF
    #!/bin/bash

    sudo yum update -y
    sudo yum install amazon-cloudwatch-agent -y
    sudo dnf install rsyslog -y
    sudo systemctl enable rsyslog --now
    sudo tee /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF_CONFIG'
    {
      "logs": {
        "logs_collected": {
          "files": {
            "collect_list": [
              {
                "file_path": "/var/log/messages",
                "log_group_name": "${aws_cloudwatch_log_group.ec2_logs-ec2-2.name}",
                "log_stream_name": "user-data-errors"
              }
            ]
          }
        }
      },
      "metrics": {
        "append_dimensions": {
          "InstanceId": "$${aws:InstanceId}"
        },
        "metrics_collected": {
          "mem": {
            "measurement": [
              "mem_used_percent"
            ],
            "metrics_collection_interval": 60,
            "resources": [
              "*"
            ]
          },
           "disk": {
            "measurement": [
              "disk_used_percent"
            ],
            "metrics_collection_interval": 60,
            "resources": [
              "/"
            ]
          }
        }
      }
    }
    EOF_CONFIG

    sudo systemctl enable amazon-cloudwatch-agent
    sudo systemctl start amazon-cloudwatch-agent
EOF
}
resource "aws_instance" "ec2-3" {
  ami                    = var.ami_value
  instance_type          = var.instance_type_value
  key_name               = var.key_name
  monitoring             = true
  vpc_security_group_ids = [aws_security_group.webSg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_instance_profile.name
   tags = {
    Name = "ec2-3"
  }


  user_data = <<-EOF
    #!/bin/bash

    sudo yum update -y
    sudo yum install amazon-cloudwatch-agent -y
    sudo dnf install rsyslog -y
    sudo systemctl enable rsyslog --now
    sudo tee /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF_CONFIG'
    {
      "logs": {
        "logs_collected": {
          "files": {
            "collect_list": [
              {
                "file_path": "/var/log/messages",
                "log_group_name": "${aws_cloudwatch_log_group.ec2_logs-ec2-2.name}",
                "log_stream_name": "user-data-errors"
              }
            ]
          }
        }
      },
      "metrics": {
        "append_dimensions": {
          "InstanceId": "$${aws:InstanceId}"
        },
        "metrics_collected": {
          "mem": {
            "measurement": [
              "mem_used_percent"
            ],
            "metrics_collection_interval": 60,
            "resources": [
              "*"
            ]
          },
           "disk": {
            "measurement": [
              "disk_used_percent"
            ],
            "metrics_collection_interval": 60,
            "resources": [
              "/"
            ]
          }
        }
      }
    }
    EOF_CONFIG

    sudo systemctl enable amazon-cloudwatch-agent
    sudo systemctl start amazon-cloudwatch-agent
EOF
}
resource "aws_sns_topic" "error_notifications" {
  name = "error_notifications"
}
resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.error_notifications.arn
  protocol  = "email"
  endpoint  = var.email_subscription 
}
resource "aws_cloudwatch_metric_alarm" "error_alarm_ec2_1" {
  alarm_name          = "error_alarm_ec2_1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors" 
  namespace           = "AWS/Logs"
  period              = 300
  statistic           = "Sum"
  threshold           = 1 
  alarm_description   = "Alarm when errors occur in ec2-1 logs"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]
  dimensions = {
    LogGroupName = aws_cloudwatch_log_group.ec2_logs-ec2-1.name
  }
}
resource "aws_cloudwatch_metric_alarm" "error_alarm_ec2_2" {
  alarm_name          = "error_alarm_ec2_2"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors" 
  namespace           = "AWS/Logs"
  period              = 300
  statistic           = "Sum"
  threshold           = 1 
  alarm_description   = "Alarm when errors occur in ec2-2 logs"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]
  dimensions = {
    LogGroupName = aws_cloudwatch_log_group.ec2_logs-ec2-2.name
  }
}
resource "aws_cloudwatch_metric_alarm" "error_alarm_ec2_3" {
  alarm_name          = "error_alarm_ec2_2"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors" 
  namespace           = "AWS/Logs"
  period              = 300
  statistic           = "Sum"
  threshold           = 1 
  alarm_description   = "Alarm when errors occur in ec2-3 logs"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]
  dimensions = {
    LogGroupName = aws_cloudwatch_log_group.ec2_logs-ec2-3.name
  }
}



resource "aws_iam_policy_attachment" "sns_publish_access" {
  name       = "sns_publish_access"
  roles      = [aws_iam_role.ec2_role.name]
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
}

resource "aws_cloudwatch_metric_alarm" "cpu_alarm-ec2-1-RED" {
  alarm_name          = "CPUUtilizationAlarm-ec2-1-RED"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alarm when CPU utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]
  
  dimensions = {
    InstanceId = aws_instance.ec2-1.id
  }
}

resource "aws_cloudwatch_metric_alarm" "memory_alarm-ec2-1-RED" {
  alarm_name          = "MemoryUtilizationAlarm-ec2-1-RED"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "mem_used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alarm when memory utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]

  dimensions = {
    InstanceId = aws_instance.ec2-1.id
  }
}

resource "aws_cloudwatch_metric_alarm" "disk_alarm-ec2-1-RED" {
  alarm_name          = "DiskUtilizationAlarm-ec2-1-RED"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alarm when disk utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]

  dimensions = {
    InstanceId = aws_instance.ec2-1.id
    Filesystem = "/"
  }
}

resource "aws_cloudwatch_metric_alarm" "cpu_alarm-ec2-1-AMBER" {
  alarm_name          = "CPUUtilizationAlarm-ec2-1-AMBER"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 60
  alarm_description   = "Alarm when CPU utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]
  
  dimensions = {
    InstanceId = aws_instance.ec2-1.id
  }
}

resource "aws_cloudwatch_metric_alarm" "memory_alarm-ec2-1-AMBER" {
  alarm_name          = "MemoryUtilizationAlarm-ec2-1-ABMER"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "mem_used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 60
  alarm_description   = "Alarm when memory utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]

  dimensions = {
    InstanceId = aws_instance.ec2-1.id
  }
}

resource "aws_cloudwatch_metric_alarm" "disk_alarm-ec2-1-AMBER" {
  alarm_name          = "DiskUtilizationAlarm-ec2-1-AMBER"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 60
  alarm_description   = "Alarm when disk utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]

  dimensions = {
    InstanceId = aws_instance.ec2-1.id
    Filesystem = "/"
  }
}


#################################################################3
resource "aws_cloudwatch_metric_alarm" "cpu_alarm-ec2-2-RED" {
  alarm_name          = "CPUUtilizationAlarm-ec2-2-RED"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alarm when CPU utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]
  
  dimensions = {
    InstanceId = aws_instance.ec2-2.id
  }
}

resource "aws_cloudwatch_metric_alarm" "memory_alarm-ec2-2-RED" {
  alarm_name          = "MemoryUtilizationAlarm-ec2-2-RED"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "mem_used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alarm when memory utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]

  dimensions = {
    InstanceId = aws_instance.ec2-2.id
  }
}

resource "aws_cloudwatch_metric_alarm" "disk_alarm-ec2-2-RED" {
  alarm_name          = "DiskUtilizationAlarm-ec2-2-RED"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alarm when disk utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]

  dimensions = {
    InstanceId = aws_instance.ec2-2.id
    Filesystem = "/"
  }
}

resource "aws_cloudwatch_metric_alarm" "cpu_alarm-ec2-2-AMBER" {
  alarm_name          = "CPUUtilizationAlarm-ec2-2-AMBER"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 60
  alarm_description   = "Alarm when CPU utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]
  
  dimensions = {
    InstanceId = aws_instance.ec2-2.id
  }
}

resource "aws_cloudwatch_metric_alarm" "memory_alarm-ec2-2-AMBER" {
  alarm_name          = "MemoryUtilizationAlarm-ec2-2-ABMER"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "mem_used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 60
  alarm_description   = "Alarm when memory utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]

  dimensions = {
    InstanceId = aws_instance.ec2-2.id
  }
}

resource "aws_cloudwatch_metric_alarm" "disk_alarm-ec2-2-AMBER" {
  alarm_name          = "DiskUtilizationAlarm-ec2-2-AMBER"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 60
  alarm_description   = "Alarm when disk utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]

  dimensions = {
    InstanceId = aws_instance.ec2-2.id
    Filesystem = "/"
  }
}

################################################

resource "aws_cloudwatch_metric_alarm" "cpu_alarm-ec2-3-RED" {
  alarm_name          = "CPUUtilizationAlarm-ec2-3-RED"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alarm when CPU utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]
  
  dimensions = {
    InstanceId = aws_instance.ec2-3.id
  }
}

resource "aws_cloudwatch_metric_alarm" "memory_alarm-ec2-3-RED" {
  alarm_name          = "MemoryUtilizationAlarm-ec2-3-RED"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "mem_used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alarm when memory utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]

  dimensions = {
    InstanceId = aws_instance.ec2-3.id
  }
}

resource "aws_cloudwatch_metric_alarm" "disk_alarm-ec2-3-RED" {
  alarm_name          = "DiskUtilizationAlarm-ec2-3-RED"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alarm when disk utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]

  dimensions = {
    InstanceId = aws_instance.ec2-3.id
    Filesystem = "/"
  }
}

resource "aws_cloudwatch_metric_alarm" "cpu_alarm-ec2-3-AMBER" {
  alarm_name          = "CPUUtilizationAlarm-ec2-3-AMBER"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 60
  alarm_description   = "Alarm when CPU utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]
  
  dimensions = {
    InstanceId = aws_instance.ec2-3.id
  }
}

resource "aws_cloudwatch_metric_alarm" "memory_alarm-ec2-3-AMBER" {
  alarm_name          = "MemoryUtilizationAlarm-ec2-3-ABMER"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "mem_used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 60
  alarm_description   = "Alarm when memory utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]

  dimensions = {
    InstanceId = aws_instance.ec2-3.id
  }
}

resource "aws_cloudwatch_metric_alarm" "disk_alarm-ec2-3-AMBER" {
  alarm_name          = "DiskUtilizationAlarm-ec2-3-AMBER"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 60
  alarm_description   = "Alarm when disk utilization is greater than or equal to 60%"
  alarm_actions       = [aws_sns_topic.error_notifications.arn]

  dimensions = {
    InstanceId = aws_instance.ec2-3.id
    Filesystem = "/"
  }
}
####metric stream

resource "aws_cloudwatch_metric_stream" "main" {
  name          = "my-metric-stream"
  role_arn      = aws_iam_role.metric_stream_to_firehose.arn
  firehose_arn  = aws_kinesis_firehose_delivery_stream.s3_stream.arn
  output_format = "json"

   include_filter {
    namespace    = "CWAgent"  
    metric_names = ["mem_used_percent"]
  }
  include_filter {
    namespace    = "CWAgent"
    metric_names = ["disk_used_percent"]  
  }
  include_filter {
    namespace    = "AWS/EC2"
    metric_names = ["CPUUtilization", "NetworkOut", "NetworkIn"]
  }
}



data "aws_iam_policy_document" "streams_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["streams.metrics.cloudwatch.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "metric_stream_to_firehose" {
  name               = "metric_stream_to_firehose_role"
  assume_role_policy = data.aws_iam_policy_document.streams_assume_role.json
}

data "aws_iam_policy_document" "metric_stream_to_firehose" {
  statement {
    effect = "Allow"

    actions = [
      "firehose:PutRecord",
      "firehose:PutRecordBatch",
      "firehose:CreateDeliveryStream",
    ]

    resources = [aws_kinesis_firehose_delivery_stream.s3_stream.arn]
  }
}
resource "aws_iam_role_policy" "metric_stream_to_firehose" {
  name   = "default"
  role   = aws_iam_role.metric_stream_to_firehose.id
  policy = data.aws_iam_policy_document.metric_stream_to_firehose.json
}

resource "aws_s3_bucket" "mad_mobile_tasks3" {
  bucket = "mad_mobile_tasks3"

  lifecycle_rule {
    id      = "log_retention_rule"
    enabled = true

    expiration {
      days = 7  
    }
  }
}



data "aws_iam_policy_document" "firehose_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "firehose_to_s3" {
  assume_role_policy = data.aws_iam_policy_document.firehose_assume_role.json
}

data "aws_iam_policy_document" "firehose_to_s3" {
  statement {
    effect = "Allow"

    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject",
    ]

    resources = [
      aws_s3_bucket.mad_mobile_tasks3.arn,
      "${aws_s3_bucket.mad_mobile_tasks3.arn}/*",
    ]
  }
}

resource "aws_iam_role_policy" "firehose_to_s3" {
  name   = "default"
  role   = aws_iam_role.firehose_to_s3.id
  policy = data.aws_iam_policy_document.firehose_to_s3.json
}

resource "aws_kinesis_firehose_delivery_stream" "s3_stream" {
  name        = "metric-stream-test-stream"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_to_s3.arn
    bucket_arn = aws_s3_bucket.mad_mobile_tasks3.arn
  }
}

resource "aws_iam_role" "lambda_role" {
  name = "lambda_execution_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}


resource "aws_iam_policy" "lambda_policy" {
  name        = "lambda_policy"
  description = "Allows necessary permissions for Lambda function"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "ec2:DescribeInstances",
        "cloudwatch:GetMetricStatistics",
        "sns:Publish"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}


resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}


resource "aws_lambda_function" "ec2_metrics_lambda" {
  filename      = "my-deployment.zip"  
  function_name = "ec2_metrics_lambda"
  role          = aws_iam_role.lambda_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.11"
  timeout       = 9

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.error_notifications.arn
    }
  }
}


resource "aws_cloudwatch_event_rule" "lambda_trigger_rule" {
  name                = "lambda_trigger_rule"
  description         = "Triggers Lambda function every 5 minutes"
  schedule_expression = "cron(0 0 ? * 1 *)"
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.lambda_trigger_rule.name
  target_id = "ec2_metrics_lambda"
  arn       = aws_lambda_function.ec2_metrics_lambda.arn
}

resource "aws_lambda_permission" "allow_cloudwatch" {
    statement_id = "AllowExecutionFromCloudWatch"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.ec2_metrics_lambda.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.lambda_trigger_rule.arn
}




