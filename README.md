# AWS Account Cleanup Script 🧹

## Overview
This script is designed to help clean up unnecessary AWS resources such as EC2 instances, S3 buckets, Lambda functions, IAM users, and more. It is intended for personal account usage, especially for avoiding unnecessary billing due to idle resources. ⚠️ Do not use in production environments. Always ensure to test thoroughly and obtain necessary permissions if using within a corporate environment.

For full documentation, visit: [updating soon](xyz.xom).

## Basic Usage
### Prerequisites
1 **Install Dependencies**:
Make sure you have boto3 installed. You can install it via pip:
```
pip install boto3
```

2 **AWS Credentials Setup**:
Configure your AWS credentials to allow access to the required services. Add the credentials to your machine using:
```
nano ~/.aws/credentials
```
Add the following or replace in the file:
```
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
```

3 **Run the Script**: Use the following command to run the cleanup script:

```
python aws_account_cleaner.py <region_name> <username>
```
**Example:**

```
python aws_account_cleaner.py us-west-2 admin
```

This will:

- Terminate all EC2 instances
- Delete S3 buckets and their contents
- Remove Lambda functions
- Clean up IAM users, roles, policies
- Delete RDS instances, DynamoDB tables, and CloudFormation stacks
  
## Important Notes ⚠️
- **Personal Use Only**: This script is intended for use on personal AWS accounts. It is not designed for production or corporate use.
- **Test First**: Always test the script in a non-production environment before using it on any critical resources.
- **Permission Required**: If using in a corporate environment, ensure you have the necessary permissions before running the script. Misuse of this script could lead to unintended resource deletion and service disruption.
  
For full documentation, visit: [updating soon](xyz.xom).


