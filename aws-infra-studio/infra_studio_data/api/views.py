from django.http import JsonResponse

from rest_framework.views import APIView
import boto3
from rest_framework import status
import csv
from rest_framework.response import Response
from django.http import HttpResponse
import os
import json
import argparse
import dateutil.relativedelta as dateutil
import datetime
import os
import sys
from rest_framework.permissions import AllowAny,AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.shortcuts import HttpResponse
import boto3
import botocore.exceptions
from django.conf import settings
from datetime import datetime, timedelta , date
from django.shortcuts import render
import csv
import smtplib
from json import JSONEncoder
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.mime.multipart import MIMEMultipart
from api.serializers import *
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password,check_password
from .serializers import *
class Registeruser(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def post(self,request):
        serializer=UserSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({'status':403,'errors':serializer.errors})
        password = make_password(request.data['password'])
        serializer.validated_data['password'] = password
        serializer.save()
        
        # user=User.objects.get(username=serializer.data['username'])
        # token_obj,_=Token.objects.get_or_create(user=user)
        return Response({'status':200 ,'payload':serializer.data,'message':'succesfully registered'})
#User
class LoginView(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def post(self, request):
        serializer = User(data=request.data)
        serializer.is_valid()
        email = request.data["email"]
        password = request.data["password"]
        validation = User.objects.filter(email=email)

        if validation:
            user = User.objects.get(email=serializer.data['email'])
            # Check if the provided password matches the hashed password in the database
            if check_password(password, user.password):
                refresh = RefreshToken.for_user(user)
                return Response({
                    'message':'Successfully logged in',
                    'access': str(refresh.access_token)
                })
            else:
                return Response({"message": "Invalid email or password"}, status.HTTP_403_FORBIDDEN)
        else:
            return Response({"message": "Invalid email or password"}, status.HTTP_403_FORBIDDEN)
    def get(self,request):
        users=User.objects.all()
        user_serializer=UserSerializer(users,many=True)
        return Response(user_serializer.data)

class CustomJSONEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)
class CreateFolder(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def post(self, request, format=None):
        folder_name = request.data.get('name')
        if folder_name:
            folder, created = Folder.objects.get_or_create(name=folder_name)
            if created:
                return Response({'message': f'Folder "{folder_name}" created successfully.'}, status=status.HTTP_201_CREATED)
            else:
                return Response({'message': f'Folder "{folder_name}" already exists.'}, status=status.HTTP_409_CONFLICT)
        else:
            return Response({'error': 'Please provide a folder_name in the request data.'}, status=status.HTTP_400_BAD_REQUEST)
class EC2_Memory_utilization(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get_last_activity_time(self, instance_state, launch_time):
        if instance_state == 'running':
            return datetime.utcnow()
        elif instance_state == 'stopped':
            # Use the instance's launch time as an estimate for last activity time
            return launch_time
        else:
            # Handle other states as needed
            return None

    def get(self, request):
        try:
            all_utilization_info = []

            regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]

            for region_name in regions:
                ec2_client = boto3.client('ec2', region_name=region_name)

                response = ec2_client.describe_instances()
                
                

                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']
                        instance_type = instance['InstanceType']
                        state = instance['State']['Name']
                        launch_time = instance['LaunchTime']
                        vpc_id = instance.get('VpcId', 'N/A')  # Get VPC ID or 'N/A' if not available
                        subnet_id = instance.get('SubnetId', 'N/A')  # Get Subnet ID or 'N/A' if not available
                        platform = instance.get('Platform', 'N/A')  # Get Platform or 'N/A' if not available
                        security_groups = [sg['GroupName'] for sg in instance['SecurityGroups']]  # Get Security Groups

                        block_device_mappings = instance.get('BlockDeviceMappings', [])
                        volumes = [{"Volume ID": bd["Ebs"]["VolumeId"]} for bd in block_device_mappings]

                        last_activity_time = self.get_last_activity_time(state, launch_time)

                        cloudwatch_client = boto3.client('cloudwatch', region_name=region_name)

                        end_time = datetime.utcnow()
                        start_time = end_time - timedelta(days=30)

                        all_utilization_info.append({
                            'region': region_name,
                            'instance_id': instance_id,
                            'instance_type': instance_type,
                            'state': state,
                            'vpc_id': vpc_id,
                            'subnet_id': subnet_id,
                            'platform': platform,
                            'security_groups': security_groups,
                            'volumes': volumes,  
                            'last_activity_time': last_activity_time,
                        })

            all_utilization_info.sort(key=lambda x: (x['state'], x['last_activity_time'] or datetime.min))
            for instance_info in all_utilization_info:
                if instance_info['last_activity_time']:
                    instance_info['last_activity_time'] = str(instance_info['last_activity_time']).split("T")[0]
            response_json = json.dumps(all_utilization_info, indent=4, cls=CustomJSONEncoder)

            response = HttpResponse(response_json, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
cloudwatch_client = boto3.client('cloudwatch')
end_time = datetime.utcnow()
start_time = end_time - timedelta(days=30)
class RDSData(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self, request):
        try:
            rds_client = boto3.client('rds')
            regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]

            # Header for the CSV file
            header = "Region,DBInstanceIdentifier,Status,Role,Engine,Region & AZ,Size,Actions,CPU,Current Activity,Maintenance,VPC,Multi-AZ,DBInstanceClass,DBConnectionsReadWrite,Storage"

            # Initialize data list with header
            data = [header]

            # Loop through each region
            for region in regions:

                # Initialize Boto3 client for RDS in the current region
                rds_client_region = boto3.client('rds', region_name=region)

                # Fetch RDS instances in the region
                instances = rds_client_region.describe_db_instances()['DBInstances']

                # Loop through each RDS instance and gather details
                for instance in instances:
                    db_identifier = instance['DBInstanceIdentifier']
                    status = instance['DBInstanceStatus']
                    role = instance['IAMDatabaseAuthenticationEnabled']  # Assuming you want IAM Database Authentication status
                    engine = instance['Engine']
                    region_az = f"{region}/{instance['AvailabilityZone']}"
                    size = instance['DBInstanceClass']
                    actions = instance['PendingModifiedValues']
                    cpu = instance.get('ProcessorFeatures', [{'Name': 'N/A'}])[0]['Name']  # Handle missing 'ProcessorFeatures'
                    current_activity = instance.get('PendingModifiedValues', 'N/A')
                    maintenance = instance['AutoMinorVersionUpgrade']
                    vpc = instance['DBSubnetGroup']['VpcId']
                    multi_az = instance['MultiAZ']
                    db_instance_class = instance['DBInstanceClass']
                    db_connections_read_write = instance.get('ReadReplicaSourceDBInstanceIdentifier', 'N/A')
                    storage = instance.get('AllocatedStorage', 'N/A')

                    instance_data = {
                        'Region': region,
                        'DBInstanceIdentifier': db_identifier,
                        'Status': status,
                        'Role': role,
                        'Engine': engine,
                        'Region & AZ': region_az,
                        'Size': size,
                        'Actions': actions,
                        'CPU': cpu,
                        'Current Activity': current_activity,
                        'Maintenance': maintenance,
                        'VPC': vpc,
                        'Multi-AZ': multi_az,
                        'DBInstanceClass': db_instance_class,
                        'DBConnectionsReadWrite': db_connections_read_write,
                        'Storage_in_GiB': storage,
                    }

                    data.append(instance_data)

            response_data = {
                'RDSInstanceData': data,
                'Timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:S"),
            }
            response_json = json.dumps(response_data, indent=4)

            # Set the response content type to JSON
            response = HttpResponse(response_json, content_type='application/json')

            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class Secrets_data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self,request):
        try:
    # Get a list of all available AWS regions
            regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]

            all_secrets = []

            for region in regions:
                

                # Create a Boto3 client for the AWS Secrets Manager service in the current region
                secrets_manager_client = boto3.client('secretsmanager', region_name=region)

                # List all secrets in the current region
                response = secrets_manager_client.list_secrets()

                secrets = response['SecretList']
                
                for secret in secrets:
                    secret_name = secret['Name']
                    secret_arn = secret['ARN']

                    total_secrets = len(secrets)
                    all_secrets.append({
                        'Region': region,
                        'Secret Name': secret_name,
                        'Secret ARN': secret_arn,
                        'Resource_count':total_secrets,
                    })

            
            response_json = json.dumps(all_secrets, indent=4)
            response = HttpResponse(response_json, content_type='application/json')
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
def get_ecr_repositories(ecr_client):
    response = ecr_client.describe_repositories()
    return response['repositories']

def get_repository_images(ecr_client, repository_name):
    response = ecr_client.describe_images(repositoryName=repository_name)
    return response['imageDetails']

def fetch_ecr_data_for_regions(request):
    ecr_data_list = []
    regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]
    for region in regions:
        ecr_client = boto3.client('ecr', region_name=region)
        repositories = get_ecr_repositories(ecr_client)

        for repository in repositories:
            repository_name = repository['repositoryName']
            images = get_repository_images(ecr_client, repository_name)
            ecr_data = {
                "Region": region,
                "Repository": repository_name,
                "CreatedAt": repository['createdAt'].isoformat(),
                "TagImmutability": repository['imageTagMutability'],
                "ScanFrequency": repository.get('imageScanningConfiguration', {}).get('scanOnPush'),
                "EncryptionType": repository.get('encryptionConfiguration', {}).get('encryptionType'),
                "PullThroughCache": repository.get('imageScanningConfiguration', {}).get('scanOnPush'),
                "Images": []
            }
            for image in images:
                image_pushedtime = image.get('imagePushedAt').isoformat() if image.get('imagePushedAt') else None
                image_lastpulltime = image.get('lastRecordedPullTime').isoformat() if image.get('lastRecordedPullTime') else None
                image_tags = image.get('imageTags', ['<no tags>'])
                image_size = image['imageSizeInBytes']
                image_size_mb = image_size / (1024 * 1024)
                image_artifact_type = image.get('imageManifestMediaType', 'Unknown')

                ecr_data_image = {
                    "Tags": image_tags,
                    "Size_in_mb": image_size_mb,
                    "LastPullTime": image_lastpulltime,
                    "PushedAtTime": image_pushedtime,
                    "ArtifactType": image_artifact_type,
                }
                ecr_data["Images"].append(ecr_data_image)

            ecr_data_list.append(ecr_data)

    response_json = json.dumps(ecr_data_list, indent=4)
    response = HttpResponse(response_json, content_type='application/json')

    return response

class Get_ECR_Data(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]
    def get(self, request):
        try:
            return fetch_ecr_data_for_regions(request)
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class Get_S3_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self, request):
        try:
            s3_client = boto3.client('s3')

            three_days_ago = datetime.now() - timedelta(days=3)
            date = three_days_ago.strftime('%Y-%m-%d')

            # Get list of all S3 buckets
            response = s3_client.list_buckets()

            # Create a list to store bucket data
            bucket_data = []

            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                try:
                    # Get bucket size and last modified date
                    bucket_objects = s3_client.list_objects_v2(Bucket=bucket_name)
                    total_size = 0
                    last_modified = None
                    object_count = 0
                    storage_class = None

                    if 'Contents' in bucket_objects:
                        object_count = len(bucket_objects['Contents'])
                        for obj in bucket_objects['Contents']:
                            storage_class = obj['StorageClass']
                            total_size += obj['Size']
                            if last_modified is None or obj['LastModified'] > last_modified:
                                last_modified = obj['LastModified']

                    # Convert last modified date to a readable format without time
                    formatted_last_modified = last_modified.strftime(
                        '%Y-%m-%d') if last_modified else 'N/A'
                    
                    # Check if the bucket's last modified date is earlier than the specified date
                    if formatted_last_modified < date:
                        bucket_info = {
                            "Bucket": bucket_name,
                            "Total Storage Size (Bytes)": total_size,
                            "Last Modified Date": formatted_last_modified,
                            "Storage Class": storage_class,
                            "Object Count": object_count
                        }
                        bucket_data.append(bucket_info)
                except Exception as e:
                    print("Error:", e)

            # Convert the bucket_data list to JSON format
            json_data = json.dumps(bucket_data, indent=4)

            response = HttpResponse(json_data, content_type='application/json')
            
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
# def fetch_lambda_metrics(lambda_function_name, region):
#     try:
#         cloudwatch_client = boto3.client('cloudwatch', region_name=region)
#         end_time = datetime.utcnow()
#         start_time = end_time - timedelta(days=30)
#         response = cloudwatch_client.get_metric_data(
#             MetricDataQueries=[
#                 {
#                     'Id': 'invocations',
#                     'MetricStat': {
#                         'Metric': {
#                             'Namespace': 'AWS/Lambda',
#                             'MetricName': 'Invocations',
#                             'Dimensions': [{'Name': 'FunctionName', 'Value': lambda_function_name}]
#                         },
#                         'Period': 3600,
#                         'Stat': 'Sum'
#                     }
#                 },
#                 {
#                     'Id': 'duration',
#                     'MetricStat': {
#                         'Metric': {
#                             'Namespace': 'AWS/Lambda',
#                             'MetricName': 'Duration',
#                             'Dimensions': [{'Name': 'FunctionName', 'Value': lambda_function_name}]
#                         },
#                         'Period': 3600,
#                         'Stat': 'Average'
#                     }
#                 },
#                 {
#                     'Id': 'concurrent_executions',
#                     'MetricStat': {
#                         'Metric': {
#                             'Namespace': 'AWS/Lambda',
#                             'MetricName': 'ConcurrentExecutions',
#                             'Dimensions': [{'Name': 'FunctionName', 'Value': lambda_function_name}]
#                         },
#                         'Period': 3600,
#                         'Stat': 'Average'
#                     }
#                 }
#             ],
#             StartTime=start_time,
#             EndTime=end_time,
#         )

#         invocations = response['MetricDataResults'][0]['Values']
#         avg_duration = response['MetricDataResults'][1]['Values']
#         concurrent_executions = response['MetricDataResults'][2]['Values']

#         return invocations, avg_duration, concurrent_executions

#     except Exception as e:
#         print(f"An error occurred while fetching metrics for {lambda_function_name}: {e}")
#         return None, None, None

class LambdaMetricsView(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self, request):
        try:
            lambda_client = boto3.client('lambda')
            functions = lambda_client.list_functions()

            lambda_data = []

            for function in functions['Functions']:
                function_name = function['FunctionName']
                region = function['FunctionArn'].split(':')[3]
                description = function.get('Description', 'N/A')
                memory = function['MemorySize']
                ephemeral_storage = function['PackageType']
                timeout = function['Timeout']
                

                # You can keep the existing code for fetching metrics
                #invocations, avg_duration, concurrent_executions = fetch_lambda_metrics(function_name, region)

                lambda_data.append({
                    "FunctionName": function_name,
                    "Region": region,
                    "Description": description,
                    "Memory": memory,
                    "EphemeralStorage": ephemeral_storage,
                    "Timeout": timeout,
                    
                    
                })

            response_json = json.dumps(lambda_data, indent=4)
            response = HttpResponse(response_json, content_type='application/json')
            
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
        
def get_month_year(date):
    return date.strftime('%b-%y')
class FetchAWSCostView(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self, request):
        try:
            client = boto3.client('ce', region_name='us-east-1')  # Using the Cost Explorer client

            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)  # Fetch data for the last 3 months

            response = client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',  # Monthly data
                Metrics=['UnblendedCost'],  # Cost data
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    },
                    {
                        'Type': 'DIMENSION',
                        'Key': 'REGION'
                    }
                ]
            )

            cost_data = response['ResultsByTime']
            current_date = datetime.now().strftime("%Y-%m-%d")
            dynamic_filename = f"cost_details_{current_date}.csv"
            response = HttpResponse(content_type='text/csv')
            

            writer = csv.writer(response)
            writer.writerow(['Date', 'Service', 'Region', 'Amount', 'Unit'])

            total_cost = 0

            for entry in cost_data:
                date = entry['TimePeriod']['Start']
                groups = entry['Groups']

                for group in groups:
                    service = group['Keys'][0]
                    region = group['Keys'][1]
                    cost = float(group['Metrics']['UnblendedCost']['Amount'])

                    total_cost += cost

                    writer.writerow([get_month_year(datetime.strptime(date, '%Y-%m-%d')), service, region, cost, 'USD'])

            writer.writerow(['Total', '', '', total_cost, 'USD'])

            return response

        except Exception as e:
            return HttpResponse(f"An error occurred: {e}")
import tempfile
def send_email(subject, message, to_email,attachment_path):
    try:
        # Configure SMTP server settings
        smtp_server = settings.EMAIL_HOST
        smtp_port = settings.EMAIL_PORT
        smtp_username = settings.EMAIL_HOST_USER
        smtp_password = settings.EMAIL_HOST_PASSWORD

        # Create an SMTP connection
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)

        # Create the email message
        msg = MIMEMultipart()
        msg['From'] = smtp_username
        msg['To'] = to_email
        msg['Subject'] = subject

        # Attach the message to the email
        msg.attach(MIMEText(message, 'plain'))

        # Attach the CSV file as an attachment
        with open(attachment_path, 'rb') as csv_file:
            attachment = MIMEBase('application', 'octet-stream')
            attachment.set_payload(csv_file.read())
            encoders.encode_base64(attachment)
            attachment.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(attachment_path)}"')
            msg.attach(attachment)

        # Send the email
        server.sendmail(smtp_username, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        return ("Email sending error:", str(e))

class Send_cost_Email(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def post(self, request):
        try:
            recipient_email = request.data.get('recipient_email')  # Get recipient email from frontend
            if recipient_email:
                subject = "AWS Cost Report"
                current_date = datetime.now().strftime("%Y-%m-%d")
                # Call the get method of FetchAWSCostView to retrieve the cost report
                cost_report_response = FetchAWSCostView().get(request)
                custom_file_name_prefix = f"AWS_Cost_Report{current_date}"
                if cost_report_response.status_code == 200:
                    # Generate a temporary CSV file and write the cost report content to it
                    temp_csv_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.csv',prefix=custom_file_name_prefix)
                    temp_csv_file.write(cost_report_response.content.decode('utf-8'))
                    temp_csv_file.close()
                    
                    # Create the email message
                    message = f"Please find the attached AWS cost report."
                    send_email(subject, message, recipient_email, temp_csv_file.name)
                    
                    # Remove the temporary CSV file after sending the email
                    os.unlink(temp_csv_file.name)
                    
                    return JsonResponse({'message': 'Email sent successfully'})
                else:
                    return JsonResponse({'error': 'Failed to generate the cost report'}, status=500)
            else:
                return JsonResponse({'error': 'Recipient email address not provided'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
class Get_VPCData(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self, request):
        try:
            aws_regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]

            # Create a dictionary to store information for each region
            region_info = {}

            # Iterate through each region
            for region in aws_regions:
                ec2_client_region = boto3.client('ec2', region_name=region)
                region_info[region] = []

                # Retrieve VPC details for the current region
                vpcs_response = ec2_client_region.describe_vpcs()

                # Collect VPC details for the current region
                for vpc in vpcs_response['Vpcs']:
                    vpc_data = {
                        'VPC ID': vpc['VpcId'],
                        'CIDR Block': vpc['CidrBlock'],
                        'Subnets': [],
                        'Internet Gateways': [],
                        'NAT Gateways': [],
                        'Route Tables': [],
                        'VPC Peering Connections': [],
                        'Network ACLs': [],
                        'Security Groups': [],
                        'Egress-only Internet Gateways': [],
                        'Customer Gateways': [],
                        'DHCP Option Sets': [],
                        'Virtual Private Gateways': [],
                        'Endpoints': [],
                        'Site-to-Site VPN Connections': [],
                        'Endpoint Services': [],
                        'Running Instances': []
                    }

                    # Retrieve Subnet details associated with the VPC
                    subnets_response = ec2_client_region.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])
                    for subnet in subnets_response['Subnets']:
                        vpc_data['Subnets'].append({
                            'Subnet ID': subnet['SubnetId'],
                            'Location': subnet['AvailabilityZone'],
                            'CIDR Block': subnet['CidrBlock']
                        })

                    # Retrieve Internet Gateways associated with the VPC
                    internet_gateways_response = ec2_client_region.describe_internet_gateways()
                    for igw in internet_gateways_response['InternetGateways']:
                        vpc_ids = [attachment['VpcId'] for attachment in igw.get('Attachments', [])]
                        if vpc_ids:
                            VPC_ids = ", ".join(vpc_ids)
                        else:
                            VPC_ids = "Unattached"
                        vpc_data['Internet Gateways'].append({
                            'IGW ID': igw['InternetGatewayId'],
                            'VPC IDs': VPC_ids
                        })

                    # Retrieve NAT Gateways associated with the VPC
                    nat_gateways_response = ec2_client_region.describe_nat_gateways()
                    for nat_gw in nat_gateways_response['NatGateways']:
                        vpc_data['NAT Gateways'].append({
                            'NAT Gateway ID': nat_gw['NatGatewayId'],
                            'Subnet': nat_gw.get('SubnetId', 'Unattached'),
                            'Elastic IP allocation ID': nat_gw['NatGatewayAddresses'][0]['AllocationId']
                        })

                    # Retrieve Route Tables associated with the VPC
                    route_tables_response = ec2_client_region.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])
                    for route_table in route_tables_response['RouteTables']:
                        vpc_data['Route Tables'].append({
                            'Route Table ID': route_table['RouteTableId'],
                            'Routes': route_table['Routes']
                        })

                    # Retrieve VPC Peering Connections
                    peering_connections_response = ec2_client_region.describe_vpc_peering_connections()
                    for peering_connection in peering_connections_response['VpcPeeringConnections']:
                        vpc_data['VPC Peering Connections'].append({
                            'Peering Connection ID': peering_connection['VpcPeeringConnectionId'],
                            'Status': peering_connection['Status']['Code']
                        })

                    # Retrieve Network ACLs associated with the VPC
                    network_acls_response = ec2_client_region.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])
                    for network_acl in network_acls_response['NetworkAcls']:
                        vpc_data['Network ACLs'].append({
                            'Network ACL ID': network_acl['NetworkAclId'],
                            'Rules': network_acl['Entries']
                        })

                    # Retrieve Security Groups associated with the VPC
                    security_groups_response = ec2_client_region.describe_security_groups(
                        Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}]
                    )
                    for security_group in security_groups_response['SecurityGroups']:
                        vpc_data['Security Groups'].append({
                            'Security Group ID': security_group['GroupId'],
                            'Description': security_group['Description'],
                            'Ingress Rules': security_group['IpPermissions'],
                            'Egress Rules': security_group['IpPermissionsEgress']
                        })

                    # Add vpc_data to the region_info dictionary
                    region_info[region].append(vpc_data)

                # Add region_info to the response dictionary
            response_data = {"Regions": region_info}

                # Convert the result to JSON
            response_json = json.dumps(response_data, indent=4)

                # Create an HttpResponse with JSON content
            response = HttpResponse(response_json, content_type='application/json')

            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.strftime('%Y-%m-%d %H:%M:%S')
        return super().default(o)
class Get_ECS_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get (self,request):
        try:
        
            session = boto3.Session()

            
            aws_regions = session.get_available_regions('ecs')

            
            ecs_data = []

            for region in aws_regions:
                
                ecs_client = session.client('ecs', region_name=region)

                try:
                    
                    response = ecs_client.list_clusters()
                    clusters = response.get('clusterArns', [])

                    for cluster_arn in clusters:
                        try:
                            
                            cluster_description = ecs_client.describe_clusters(clusters=[cluster_arn])['clusters'][0]

                            
                            cluster_info = {
                                "Region": region,
                                "ClusterName": cluster_description['clusterName'],
                                "Status": cluster_description['status'],
                                "RegisteredContainerInstances": cluster_description['registeredContainerInstancesCount'],
                                "Services": cluster_description['activeServicesCount'],
                                "Tasks": cluster_description['runningTasksCount'],
                                "CapacityProviders": cluster_description.get('capacityProviders', []),
                            }
                            ecs_data.append(cluster_info)
                        except Exception as e:
                            return JsonResponse({'error': str(e)}, status=500)
                except Exception as e:
                    if 'UnrecognizedClientException' in str(e):
                        print(f"Skipped region {region} due to an invalid security token error.")
                        continue

            # Convert the list of ECS data to JSON
            json_data = json.dumps(ecs_data, indent=4)

            response = HttpResponse(json_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
from statistics import mean
class Get_load_balancer_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self,request):
        try:
            load_balancer_data = []

    # Get a list of all available AWS regions for ELB
            regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]

            for region in regions:
                client = boto3.client('elbv2', region_name=region)

                # List load balancers in the current region
                load_balancers = client.describe_load_balancers()

                for lb in load_balancers['LoadBalancers']:
                    lb_arn = lb['LoadBalancerArn']
                    lb_name = lb['LoadBalancerName']
                    lb_type = lb['Scheme']
                    lb_status = lb['State']['Code']
                    vpc_id = lb['VpcId']
                    ip_type = lb['IpAddressType']
                    scheme = lb['Scheme']
                    hosted_zone_id = lb['CanonicalHostedZoneId']
                    availability_zones = lb['AvailabilityZones']
                    created_time = lb['CreatedTime'].isoformat()

                    # Get subnets associated with the load balancer
                    subnets = [subnet['SubnetId'] for subnet in lb['AvailabilityZones']]

                    # Get listeners for the load balancer
                    listeners = client.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']

                    # Get security groups associated with the load balancer
                    security_groups = client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)['Attributes']

                    load_balancer_details = {
                        'Region': region,
                        'LoadBalancerName': lb_name,
                        'LoadBalancerType': lb_type,
                        'Status': lb_status,
                        'VPC': vpc_id,
                        'IPAddressType': ip_type,
                        'Scheme': scheme,
                        'HostedZone': hosted_zone_id,
                        'AvailabilityZones': availability_zones,
                        'DateCreated': created_time,
                        'Subnets': subnets,
                        'Listeners': listeners,
                        'SecurityGroups': security_groups
                    }

                    load_balancer_data.append(load_balancer_details)
                    
            response_json = json.dumps(load_balancer_data, indent=4)
            response = HttpResponse(response_json, content_type='application/json')
            
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class Get_EBS_Data(APIView):
        authentication_classes=[JWTAuthentication]
        permission_classes=[AllowAny]

        def get(self, request):
            try:
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(days=30)
                ec2_client = boto3.client('ec2')
                cloudwatch_client = boto3.client('cloudwatch')

                # Get a list of available regions
                regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

                # Initialize a list to store volume data across regions
                all_volume_data = []

                # Define the metric names for disk activity
                metric_names = ['VolumeReadOps', 'VolumeWriteOps']

                for aws_region in regions:
                    ec2_client = boto3.client('ec2', region_name=aws_region)
                    response = ec2_client.describe_volumes()

                    # Iterate through each EBS volume
                    for volume in response['Volumes']:
                        volume_id = volume['VolumeId']
                        volume_type = volume['VolumeType']
                        size_gb = volume['Size']
                        Iops = volume.get('Iops', None)  # Handle the case where 'Iops' may not be present

                        # Initialize a dictionary to store metrics for this volume
                        volume_metrics = {'VolumeId': volume_id, 'VolumeType': volume_type, 'SizeGB': size_gb, 'Iops': Iops}

                        # Retrieve and add I/O metrics for this volume
                        for metric_name in metric_names:
                            for stat in ['Average', 'Sum']:
                                metric_data = cloudwatch_client.get_metric_statistics(
                                    Namespace='AWS/EBS',
                                    MetricName=metric_name,
                                    Dimensions=[{'Name': 'VolumeId', 'Value': volume_id}],
                                    StartTime=start_time,
                                    EndTime=end_time,
                                    Period=3600,  # Adjust as needed
                                    Statistics=[stat],
                                )

                                # Extract and add the metric value to the volume_metrics dictionary
                                data_points = metric_data['Datapoints']
                                metric_value = None

                                if data_points:
                                    metric_value = data_points[0][stat]

                                volume_metrics[f'{stat} {metric_name}'] = metric_value

                        # Get information about the EC2 instance associated with the volume
                        if 'Attachments' in volume:
                            attachments = volume['Attachments']
                            if attachments:
                                # Assuming a volume is attached to one instance (for simplicity)
                                instance_id = attachments[0]['InstanceId']
                                volume_metrics['InstanceId'] = instance_id

                        # Append the volume_metrics dictionary to the all_volume_data list
                        all_volume_data.append(volume_metrics)

                response_json = json.dumps(all_volume_data, indent=4)
                response = HttpResponse(response_json, content_type='application/json')
                current_date = datetime.now().strftime("%Y-%m-%d")
                dynamic_filename = f"EBS_data_{current_date}.json"
                response['Content-Disposition'] = f'attachment; filename="{dynamic_filename}"'
                return response
            except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class Get_WAF_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get (self,request):
        try:
            wafv2_client = boto3.client('wafv2')
            ec2_client = boto3.client('ec2')
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

            # Initialize an empty list to store JSON objects
            json_response = []

            try:
                for aws_region in regions:
                    cloudwatch_client = boto3.client('cloudwatch', region_name=aws_region)  # Initialize CloudWatch client per region
                    response = wafv2_client.list_web_acls(Scope='CLOUDFRONT')
                    
                    for acl in response['WebACLs']:
                        acl_id = acl['Id']
                        name = acl['Name']

                        metric_name = 'AllowedRequests'
                        namespace = 'AWS/WAFV2'
                        rule_name = 'ALL'  # Specify 'ALL' to fetch data for all rules within the Web ACL
                        
                        dimensions = [
                            {
                                'Name': 'WebACL',
                                'Value': name,
                            },
                            {
                                'Name': 'Rule',
                                'Value': rule_name,
                            }
                        ]

                        end_time = datetime.utcnow()
                        start_time = end_time - timedelta(days=30)
                        
                        cloudwatch_response = cloudwatch_client.get_metric_data(
                            MetricDataQueries=[
                                {
                                    'Id': 'm1',
                                    'MetricStat': {
                                        'Metric': {
                                            'Namespace': namespace,
                                            'MetricName': metric_name,
                                            'Dimensions': dimensions,
                                        },
                                        'Period': 3600,
                                        'Stat': 'Average',
                                    },
                                },
                            ],
                            StartTime=start_time,
                            EndTime=end_time,
                            ScanBy='TimestampAscending',
                        )

                        if 'MetricDataResults' in cloudwatch_response:
                            for data_result in cloudwatch_response['MetricDataResults']:
                                if 'Values' in data_result:
                                    values = data_result['Values']
                                    
                                    # Create a dictionary with the collected information
                                    data_dict = {
                                        'AWS Region': aws_region,
                                        'Web ACL ID': acl_id,
                                        'Name': name,
                                        'Metric Name': metric_name,
                                        'Metric Values': values
                                    }
                                    
                                    # Append the dictionary to the JSON response list
                                    json_response.append(data_dict)
                        
            except Exception as e:
                return(f'Error: {str(e)}')

            # Serialize the JSON response list to a JSON string
            json_response_str = json.dumps(json_response, indent=4)
            response = HttpResponse(json_response_str, content_type='application/json')
            
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
def run_df_command(instance_id, ssm_client):
    # Specify the command to run
    commands = ['df -hT && lsblk -o NAME,KNAME,SIZE,MOUNTPOINT,TYPE']

    # Send the command to the instance
    response = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': commands},
    )

    # Wait for the command to complete
    command_id = response['Command']['CommandId']
    ssm_client.get_waiter('command_executed').wait(CommandId=command_id, InstanceId=instance_id)

    # Retrieve the command output
    output = ssm_client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
    return output
def parse_df_output(df_output):
    parsed_data = {}
    current_section = None

    for line in df_output:
        if line.startswith("Filesystem"):
            current_section = "Filesystem"
            parsed_data[current_section] = []
            parsed_data[current_section].append(line.strip())  # Add the header
        elif line.startswith("NAME"):
            current_section = "NAME"
            parsed_data[current_section] = []
            parsed_data[current_section].append(line.strip())  # Add the header
        elif current_section:
            if line.strip():
                parsed_data[current_section].append(line.strip())

    return parsed_data

class Get_Detailed_usage_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self,request):
        try:
    # Initialize AWS clients
            ssm_client = boto3.client('ssm')
            ec2_client_global = boto3.client('ec2', region_name='us-east-1')  # You can choose any region to list all regions
            regions = [region['RegionName'] for region in ec2_client_global.describe_regions()['Regions']]

            response_data = []  # To store the response data

            for region_name in regions:
                ec2_client = boto3.client('ec2', region_name=region_name)

                # Describe all instances in the current region
                instances = ec2_client.describe_instances()

                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']

                        # Check if the instance is running
                        if instance['State']['Name'] == 'running':
                            output = run_df_command(instance_id, ssm_client)
                            
                            # Split the output into lines
                            lines = output['StandardOutputContent'].strip().split('\n')
                            
                            instance_info = {
                                "Region": region_name,
                                "InstanceID": instance_id,
                            }
                            
                            parsed_data = parse_df_output(lines)
                            instance_info.update(parsed_data)
                            
                            response_data.append(instance_info)

            json_response_str = json.dumps(response_data, indent=4)
            response = HttpResponse(json_response_str, content_type='application/json')
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class Get_Elastic_Ip(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self,request):
        try:
            ec2 = boto3.client('ec2')

            # Get a list of all AWS regions
            regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]

            elastic_ips_data = []

            # Iterate through all regions
            for region in regions:
                # Create an EC2 client for the specific region
                ec2_client = boto3.client('ec2', region_name=region)

                # Use the describe_addresses method to get information about Elastic IPs in the region
                response = ec2_client.describe_addresses()
                print(response)

                # Iterate through the Elastic IPs in the region
                for elastic_ip_info in response['Addresses']:
                    allocation_id = elastic_ip_info['AllocationId']
                    instance_id = elastic_ip_info.get('InstanceId', 'Unattached')
                    ip_type = elastic_ip_info['PublicIp']
                    association_id = elastic_ip_info.get('AssociationId', 'N/A')
                    network_interface_id = elastic_ip_info.get('NetworkInterfaceId', 'N/A')
                    network_interface_owner_id = elastic_ip_info.get('NetworkInterfaceOwnerId', 'N/A')
                    nat_gateway_id = elastic_ip_info.get('NatGatewayId', 'N/A')
                    address_pool = elastic_ip_info.get('PublicIpv4Pool', 'N/A')

                    # Append Elastic IP data to the list
                    elastic_ips_data.append({
                        'Region': region,
                        'AllocationId': allocation_id,
                        'InstanceId': instance_id,
                        'Type': ip_type,
                        'AssociationId': association_id,
                        'NetworkInterfaceId': network_interface_id,
                        'NetworkInterfaceOwnerId': network_interface_owner_id,
                        'NATGatewayId': nat_gateway_id,
                        'AddressPool': address_pool
                    })

            # Return the Elastic IP data as a JSON response
            json_response_str = json.dumps(elastic_ips_data, indent=4)
            response = HttpResponse(json_response_str, content_type='application/json')
            return response
        except Exception as e:
                return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
from io import BytesIO
import pandas as pd
import matplotlib

import matplotlib.pyplot as plt

class GetTotalBill(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self, request):
        try:
            client = boto3.client('ce', region_name='us-east-1')

            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)

            response = client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    },
                    {
                        'Type': 'DIMENSION',
                        'Key': 'REGION'
                    }
                ]
            )

            cost_data = response['ResultsByTime']

            data = []
            for entry in cost_data:
                date = entry['TimePeriod']['Start']
                groups = entry['Groups']
                for group in groups:
                    service = group['Keys'][0]
                    region = group['Keys'][1]
                    cost = float(group['Metrics']['UnblendedCost']['Amount'])
                    data.append([date, service, region, cost])

            df = pd.DataFrame(data, columns=['Date', 'Service', 'Region', 'Cost'])

            # Prepare and return cost data as a list of dictionaries
            chart_data = []
            for date, service, cost in zip(df['Date'], df['Service'], df['Cost']):
                chart_data.append({'Date': date, 'Service': service, 'Cost': cost})

            return JsonResponse({'chart_data': chart_data})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
import concurrent.futures
class Get_APIGateway(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]
    def get(self, request):
        try:
            api_details_list = []
            regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]
            for region in regions:
                # Initialize the API Gateway client for the current region
                client = boto3.client('apigateway', region_name=region)

                try:
                    # List APIs (you may need to paginate through results if you have many APIs)
                    apis = client.get_rest_apis()
                except Exception as e:
                    print(f"Error listing APIs in region {region}: {str(e)}")
                    continue  # Skip this region and continue with the next

                # Iterate through the APIs in the current region
                for api in apis['items']:
                    api_id = api['id']
                    api_name = api['name']
                    description = api.get('description', 'N/A')
                    endpoint_type = api['endpointConfiguration'].get('types', 'N/A')
                    created_date = api['createdDate']

                    api_details = {
                        'Region': region,
                        'API Name': api_name,
                        'API ID': api_id,
                        'Description': description,
                        'Endpoint Type': endpoint_type,
                        'Created Date': created_date.isoformat(),
                    }

                    api_details_list.append(api_details)
            json_data = json.dumps(api_details_list, indent=4)

            response = HttpResponse(json_data, content_type='application/json')
            return response

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
class Get_Snapshot_Data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self, request):
        try:
            ec2_client = boto3.client('ec2')
            snapshot_data = []

            # Get a list of all AWS regions
            ec2_regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

            for region in ec2_regions:
                ec2_client = boto3.client('ec2', region_name=region)
                snapshots = ec2_client.describe_snapshots(OwnerIds=['self'])
                
                for snapshot in snapshots['Snapshots']:
                    snapshot_details = {
                        "Region": region,
                        "SnapshotID": snapshot['SnapshotId'],
                        "VolumeID": snapshot['VolumeId'],
                        "Description": snapshot['Description'],
                        "SizeGiB": snapshot['VolumeSize'],
                        "StartTime": snapshot['StartTime'].isoformat(),
                        "Progress": snapshot['Progress'],
                        "OwnerID": snapshot['OwnerId'],
                        "SnapshotStatus": snapshot.get('State', 'N/A'),
                        "ProductCodes": [code['ProductCodeId'] for code in snapshot.get('ProductCodes', [])],
                        "Encryption": snapshot.get('Encrypted', 'Not Encrypted'),
                        "KMSKeyID": snapshot.get('KmsKeyId', 'N/A'),
                        "KMSKeyAlias": 'N/A',  # You can fetch this information if needed
                        "KMSKeyARN": 'N/A',  # You can fetch this information if needed
                        "FastSnapshotRestore": snapshot.get('FastRestored', 'N/A'),
                        "StorageTier": snapshot.get('StorageTier', 'N/A'),
                    }
                    snapshot_data.append(snapshot_details)

            # Convert the list of dictionaries to a JSON string
            json_data = json.dumps(snapshot_data, indent=4)

            response = HttpResponse(json_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {e}"}, status=500)
                


from io import BytesIO
import pandas as pd
import matplotlib

import matplotlib.pyplot as plt

class GetTotalBill(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    def get(self, request):
        try:
            client = boto3.client('ce', region_name='us-east-1')

            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)

            response = client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    },
                    {
                        'Type': 'DIMENSION',
                        'Key': 'REGION'
                    }
                ]
            )

            cost_data = response['ResultsByTime']

            data = []
            for entry in cost_data:
                date = entry['TimePeriod']['Start']
                groups = entry['Groups']
                for group in groups:
                    service = group['Keys'][0]
                    region = group['Keys'][1]
                    cost = float(group['Metrics']['UnblendedCost']['Amount'])
                    data.append([date, service, region, cost])

            df = pd.DataFrame(data, columns=['Date', 'Service', 'Region', 'Cost'])

            # Prepare and return cost data as a list of dictionaries
            chart_data = []
            for date, service, cost in zip(df['Date'], df['Service'], df['Cost']):
                chart_data.append({'Date': date, 'Service': service, 'Cost': cost})

            return JsonResponse({'chart_data': chart_data})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
        
class Get_DynamoDB_data(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[AllowAny]
    

    def get(self,request):
        try:
            session = boto3.Session()

            # Create an empty list to store table information
            tables_data = []

            # Get a list of all available AWS regions
            aws_regions = session.get_available_regions('dynamodb')

            for region in aws_regions:
                # Create a DynamoDB client for the current region
                dynamodb_client = session.client('dynamodb', region_name=region)

                try:
                    # List tables in the current region
                    response = dynamodb_client.list_tables()
                    tables = response['TableNames']

                    for table_name in tables:
                        try:
                            # Describe the table to get detailed information
                            table_description = dynamodb_client.describe_table(TableName=table_name)['Table']

                            # Access and store attributes as needed
                            table_info = {
                                "Region": region,
                                "TableName": table_name,
                                "PartitionKey": table_description['KeySchema'][0]['AttributeName'],
                                "SortKey": table_description['KeySchema'][1]['AttributeName'] if len(table_description['KeySchema']) > 1 else None,
                                "CapacityMode": table_description.get('BillingModeSummary', {}).get('BillingMode', 'UNKNOWN'),
                                "TableStatus": table_description['TableStatus'],
                                "Alarms": table_description.get('AlarnDescription', 'No Alarms'),
                                "TableIndexes": table_description.get('GlobalSecondaryIndexes', 'No Global Secondary Indexes'),
                                "DynamoDBStream": table_description.get('StreamSpecification', {}).get('StreamEnabled', 'No Stream'),
                                "TimeToLiveTTL": table_description.get('TimeToLiveDescription', {}).get('TimeToLiveStatus', 'TTL not enabled'),
                                "ReplicationRegions": table_description.get('Replicas', 'No Replication'),
                                "Encryption": table_description.get('SSEDescription', {}).get('Status', 'Unknown'),
                                "DateCreated": str(table_description['CreationDateTime']),
                                "DeletionProtection": table_description.get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus', 'Not enabled'),
                                "ItemCount": table_description['ItemCount'],
                                "TableSizeBytes": table_description['TableSizeBytes'],
                                "AverageItemSizeBytes": table_description['TableSizeBytes'] / table_description['ItemCount'] if table_description['ItemCount'] > 0 else 'N/A'
                            }
                            tables_data.append(table_info)
                        except Exception as e:
                            return JsonResponse({'error': str(e)}, status=500)
                except Exception as e:
                    if 'UnrecognizedClientException' in str(e):
                        print(f"Skipped region {region} due to an invalid security token error.")
                        continue

            json_data = json.dumps(tables_data, indent=4)

            response = HttpResponse(json_data, content_type='application/json')
            return response
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


                
                
                