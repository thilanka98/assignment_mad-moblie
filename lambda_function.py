import boto3
import os
import datetime

def lambda_handler(event, context):
    # AWS services
    cloudwatch = boto3.client('cloudwatch')
    sns = boto3.client('sns')
    
    # Get EC2 instance IDs
    ec2 = boto3.resource('ec2')
    instances = ec2.instances.filter(
        Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
    )
    
    # Metrics to retrieve
    cpu_metric = 'CPUUtilization'
    memory_metric = 'mem_used_percent'
    disk_metric = 'disk_used_percent'
    network_in_metric = 'NetworkIn'
    network_out_metric = 'NetworkOut'
    
    metrics_data = []  # List to accumulate metrics data for all instances
    
    # Define start and end time for the weekly period
    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(weeks=1)
    
    for instance in instances:
        instance_id = instance.id
        instance_metrics = {
            'instance_id': instance_id,
            'cpu_average': 'N/A',
            'cpu_maximum': 'N/A',
            'cpu_minimum': 'N/A',
            'memory_average': 'N/A',
            'memory_maximum': 'N/A',
            'memory_minimum': 'N/A',
            'disk_average': 'N/A',
            'disk_maximum': 'N/A',
            'disk_minimum': 'N/A',
            'network_in_average': 'N/A',
            'network_in_maximum': 'N/A',
            'network_in_minimum': 'N/A',
            'network_out_average': 'N/A',
            'network_out_maximum': 'N/A',
            'network_out_minimum': 'N/A'
        }
        
        # Retrieve CPU Utilization
        cpu_response = cloudwatch.get_metric_statistics(
            Namespace='AWS/EC2',
            MetricName=cpu_metric,
            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,
            Statistics=['Average', 'Maximum', 'Minimum']
        )
        
        if 'Datapoints' in cpu_response and len(cpu_response['Datapoints']) > 0:
            cpu_datapoints = cpu_response['Datapoints']
            instance_metrics['cpu_average'] = sum(datapoint['Average'] for datapoint in cpu_datapoints) / len(cpu_datapoints)
            instance_metrics['cpu_maximum'] = max(datapoint['Maximum'] for datapoint in cpu_datapoints)
            instance_metrics['cpu_minimum'] = min(datapoint['Minimum'] for datapoint in cpu_datapoints)
        
        # Retrieve Memory Utilization
        memory_response = cloudwatch.get_metric_statistics(
            Namespace='CWAgent',
            MetricName=memory_metric,
            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,
            Statistics=['Average', 'Maximum', 'Minimum']
        )
        
        if 'Datapoints' in memory_response and len(memory_response['Datapoints']) > 0:
            memory_datapoints = memory_response['Datapoints']
            instance_metrics['memory_average'] = sum(datapoint['Average'] for datapoint in memory_datapoints) / len(memory_datapoints)
            instance_metrics['memory_maximum'] = max(datapoint['Maximum'] for datapoint in memory_datapoints)
            instance_metrics['memory_minimum'] = min(datapoint['Minimum'] for datapoint in memory_datapoints)
        
        # Retrieve Disk Utilization
        disk_response = cloudwatch.get_metric_statistics(
            Namespace='CWAgent',
            MetricName=disk_metric,
            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,
            Statistics=['Average', 'Maximum', 'Minimum']
        )
        
        if 'Datapoints' in disk_response and len(disk_response['Datapoints']) > 0:
            disk_datapoints = disk_response['Datapoints']
            instance_metrics['disk_average'] = sum(datapoint['Average'] for datapoint in disk_datapoints) / len(disk_datapoints)
            instance_metrics['disk_maximum'] = max(datapoint['Maximum'] for datapoint in disk_datapoints)
            instance_metrics['disk_minimum'] = min(datapoint['Minimum'] for datapoint in disk_datapoints)
        
        # Retrieve NetworkIn Utilization
        network_in_response = cloudwatch.get_metric_statistics(
            Namespace='AWS/EC2',
            MetricName=network_in_metric,
            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,
            Statistics=['Average', 'Maximum', 'Minimum']
        )
        
        if 'Datapoints' in network_in_response and len(network_in_response['Datapoints']) > 0:
            network_in_datapoints = network_in_response['Datapoints']
            instance_metrics['network_in_average'] = sum(datapoint['Average'] for datapoint in network_in_datapoints) / len(network_in_datapoints)
            instance_metrics['network_in_maximum'] = max(datapoint['Maximum'] for datapoint in network_in_datapoints)
            instance_metrics['network_in_minimum'] = min(datapoint['Minimum'] for datapoint in network_in_datapoints)
        
        # Retrieve NetworkOut Utilization
        network_out_response = cloudwatch.get_metric_statistics(
            Namespace='AWS/EC2',
            MetricName=network_out_metric,
            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,
            Statistics=['Average', 'Maximum', 'Minimum']
        )
        
        if 'Datapoints' in network_out_response and len(network_out_response['Datapoints']) > 0:
            network_out_datapoints = network_out_response['Datapoints']
            instance_metrics['network_out_average'] = sum(datapoint['Average'] for datapoint in network_out_datapoints) / len(network_out_datapoints)
            instance_metrics['network_out_maximum'] = max(datapoint['Maximum'] for datapoint in network_out_datapoints)
            instance_metrics['network_out_minimum'] = min(datapoint['Minimum'] for datapoint in network_out_datapoints)
        
        metrics_data.append(instance_metrics)
    
    # Prepare message for SNS
       # Prepare message for SNS
    message = '\n'.join([
        f"Instance ID: {data['instance_id']}\n"
        f"CPU Utilization: Avg={data['cpu_average']}, Max={data['cpu_maximum']}, Min={data['cpu_minimum']}\n"
        f"Memory Utilization: Avg={data['memory_average']}, Max={data['memory_maximum']}, Min={data['memory_minimum']}\n"
        f"Disk Utilization: Avg={data['disk_average']}, Max={data['disk_maximum']}, Min={data['disk_minimum']}\n"
        f"NetworkIn Utilization: Avg={data['network_in_average']}, Max={data['network_in_maximum']}, Min={data['network_in_minimum']}\n"
        f"NetworkOut Utilization: Avg={data['network_out_average']}, Max={data['network_out_maximum']}, Min={data['network_out_minimum']}\n"
        for data in metrics_data
    ])


    
    # Send notification via SNS
    sns.publish(
        TopicArn=os.environ['SNS_TOPIC_ARN'],
        Subject="EC2 Metrics Summary",
        Message=message
    )

    return {
        'statusCode': 200,
        'body': 'Metrics sent successfully'
    }

