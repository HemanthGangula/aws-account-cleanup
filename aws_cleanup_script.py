import boto3
from botocore.exceptions import ClientError, NoRegionError
import sys
import json
import time

def attach_admin_policy(iam_client, username):
    admin_policy_arn = 'arn:aws:iam::aws:policy/AdministratorAccess'
    try:
        iam_client.attach_user_policy(
            UserName=username,
            PolicyArn=admin_policy_arn
        )
        print(f"🔒 Attached AdministratorAccess policy to user {username}")
    except ClientError as e:
        print(f"❌ Error attaching policy: {e}")
        sys.exit(1)

def detach_admin_policy(iam_client, username):
    admin_policy_arn = 'arn:aws:iam::aws:policy/AdministratorAccess'
    try:
        iam_client.detach_user_policy(
            UserName=username,
            PolicyArn=admin_policy_arn
        )
        print(f"🔓 Detached AdministratorAccess policy from user {username}")
    except ClientError as e:
        print(f"❌ Error detaching policy: {e}")

def delete_all_resources(region_name, username):
    try:
        # Initialize a session using Amazon credentials and specified region
        session = boto3.Session(region_name=region_name or 'us-east-1')
        iam_client = session.client('iam')

        # Attach AdministratorAccess policy
        attach_admin_policy(iam_client, username)

        # Wait for policy to propagate
        print("⏳ Waiting for policy to propagate...")
        time.sleep(10)

        # List of services to clean up
        services = ['ec2', 's3', 'lambda', 'iam', 'rds', 'dynamodb', 'cloudformation', 'sns', 'cloud9', 'cloudwatch']

        for service in services:
            print(f"🧹 Cleaning up {service}...")
            
            # Get the appropriate client
            client = session.client(service)
            
            if service == 'ec2':
                # Terminate all EC2 instances
                response = client.describe_instances()
                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        client.terminate_instances(InstanceIds=[instance['InstanceId']])
                
                # Delete all EBS volumes
                volumes = client.describe_volumes()['Volumes']
                for volume in volumes:
                    client.delete_volume(VolumeId=volume['VolumeId'])
                
                # Delete all security groups
                security_groups = client.describe_security_groups()['SecurityGroups']
                for sg in security_groups:
                    if sg['GroupName'] != 'default':
                        client.delete_security_group(GroupId=sg['GroupId']) 

            elif service == 's3':
                # Delete all S3 buckets and their contents
                s3 = session.resource('s3')
                for bucket in s3.buckets.all():
                    bucket.object_versions.delete()
                    bucket.delete()

            elif service == 'lambda':
                # Delete all Lambda functions
                functions = client.list_functions()['Functions']
                for function in functions:
                    client.delete_function(FunctionName=function['FunctionName'])

            elif service == 'iam':
                # Delete IAM users, roles, and policies (except the current user)
                
                # Delete users
                for user in iam_client.list_users()['Users']:
                    if user['UserName'] != username:
                        # Detach all user policies
                        for policy in iam_client.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']:
                            iam_client.detach_user_policy(UserName=user['UserName'], PolicyArn=policy['PolicyArn'])
                        # Delete all user access keys
                        for access_key in iam_client.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']:
                            iam_client.delete_access_key(UserName=user['UserName'], AccessKeyId=access_key['AccessKeyId'])
                        # Delete the user
                        iam_client.delete_user(UserName=user['UserName'])
                        print(f"🗑️ Deleted user: {user['UserName']}")

                # Delete roles
                for role in iam_client.list_roles()['Roles']:
                    try:
                        # Detach all role policies
                        for policy in iam_client.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']:
                            iam_client.detach_role_policy(RoleName=role['RoleName'], PolicyArn=policy['PolicyArn'])
                        # Remove role from instance profiles
                        for profile in iam_client.list_instance_profiles_for_role(RoleName=role['RoleName'])['InstanceProfiles']:
                            iam_client.remove_role_from_instance_profile(
                                InstanceProfileName=profile['InstanceProfileName'],
                                RoleName=role['RoleName']
                            )
                        # Delete the role
                        iam_client.delete_role(RoleName=role['RoleName'])
                        print(f"🗑️ Deleted role: {role['RoleName']}")
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'UnmodifiableEntity':
                            print(f"⚠️ Cannot delete protected role {role['RoleName']}: {e}")
                        else:
                            print(f"❌ Error deleting role {role['RoleName']}: {e}")

                # Delete policies
                for policy in iam_client.list_policies(Scope='Local')['Policies']:
                    if policy['Arn'] != iam_client.get_user()['User']['Arn']:
                        # Detach the policy from all users, groups, and roles
                        for user in iam_client.list_entities_for_policy(PolicyArn=policy['Arn'], EntityFilter='User')['PolicyUsers']:
                            iam_client.detach_user_policy(UserName=user['UserName'], PolicyArn=policy['Arn'])
                        for group in iam_client.list_entities_for_policy(PolicyArn=policy['Arn'], EntityFilter='Group')['PolicyGroups']:
                            iam_client.detach_group_policy(GroupName=group['GroupName'], PolicyArn=policy['Arn'])
                        for role in iam_client.list_entities_for_policy(PolicyArn=policy['Arn'], EntityFilter='Role')['PolicyRoles']:
                            iam_client.detach_role_policy(RoleName=role['RoleName'], PolicyArn=policy['Arn'])
                        # Delete all versions of the policy except the default version
                        for version in iam_client.list_policy_versions(PolicyArn=policy['Arn'])['Versions']:
                            if not version['IsDefaultVersion']:
                                iam_client.delete_policy_version(PolicyArn=policy['Arn'], VersionId=version['VersionId'])
                        # Delete the policy
                        iam_client.delete_policy(PolicyArn=policy['Arn'])
                        print(f"🗑️ Deleted policy: {policy['PolicyName']}")

            elif service == 'rds':
                # Delete all RDS instances
                instances = client.describe_db_instances()['DBInstances']
                for instance in instances:
                    client.delete_db_instance(DBInstanceIdentifier=instance['DBInstanceIdentifier'], SkipFinalSnapshot=True)

            elif service == 'dynamodb':
                # Delete all DynamoDB tables
                tables = client.list_tables()['TableNames']
                for table in tables:
                    client.delete_table(TableName=table)
            
            elif service == 'sns':
                # Delete all SNS topics
                topics = client.list_topics()['Topics']
                for topic in topics:
                    client.delete_topic(TopicArn=topic['TopicArn'])
            
            elif service == 'cloud9':
                # List and delete all Cloud9 environments
                environment_ids = client.list_environments()['environmentIds']
                for env_id in environment_ids:
                    client.delete_environment(environmentId=env_id)

            elif service == 'cloudwatch':
                # Delete all CloudWatch alarms
                alarms = client.describe_alarms()['MetricAlarms']
                for alarm in alarms:
                    client.delete_alarms(AlarmNames=[alarm['AlarmName']])

                # Delete all Dashboards
                dashboards = client.list_dashboards()['DashboardEntries']
                for dashboard in dashboards:
                    client.delete_dashboards(DashboardNames=[dashboard['DashboardName']])

            elif service == 'cloudformation':
                # Delete all CloudFormation stacks
                stacks = client.list_stacks()['StackSummaries']
                for stack in stacks:
                    if stack['StackStatus'] != 'DELETE_COMPLETE':
                        client.delete_stack(StackName=stack['StackName'])

        print("✅ Cleanup complete!")

    except NoRegionError:
        print("❌ Error: No region specified. Please provide a valid AWS region.")
        sys.exit(1)
    except ClientError as e:
        print(f"❌ An error occurred: {e}")
        sys.exit(1)
    finally:
        # Always try to detach the admin policy, even if an error occurred
        detach_admin_policy(iam_client, username)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python aws_account_cleaner.py <region_name> <username>")
        print("Example: python aws_account_cleaner.py us-west-2 admin")
        sys.exit(1)
    
    region_name = sys.argv[1] if sys.argv[1] else 'us-east-1'
    username = sys.argv[2]
    delete_all_resources(region_name, username)