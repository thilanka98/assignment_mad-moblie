# aws ec2+cloudwatch+lambda+firehose project

this repo contain project

## Prerequisites

Before you begin, ensure you have the following installed:

- [Terraform](https://www.terraform.io/downloads.html)
- AWS CLI configured with appropriate permissions
    - AmazonEC2FullAccess
    - AmazonKinesisFirehoseFullAccess
    - AmazonS3FullAccess
    - AWSLambda_FullAccess
    - CloudWatchEventsFullAccess
    - CloudWatchFullAccess
    - IAMFullAccess
##Steps

1. Clone this repository:

   ```bash
   git clone https://github.com/thilanka98/assignment_mad-moblie.git

2. Navigate to the cloned directory:

   ```bash
   cd mad_mobile-assignment

3. Initialize Terraform:

   ```bash
   terraform init

4. modify the variables.tf file to customize your deployment

5. verify the Terraform configurations

   ```bash
   terraform plan

6. apply the terraform configurations

   ```bash
   terraform plan

7. after applying the configurations confirm it by typing 'yes'

8. destroy the infrastructure using this command

   ```bash
   terraform destroy

9. confirm thid step by typing 'yes'