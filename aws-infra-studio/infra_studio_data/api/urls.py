from django.urls import path
from . import views
urlpatterns = [
    path('api/studio/register/',views.Registeruser.as_view()),
    path('api/studio/login/', views.LoginView.as_view(),name='login'),
    path('api/studio/ec2_memory_data/',views.EC2_Memory_utilization.as_view(),name='ec2_memory_data'),#1 done
    #path('api/studio/cost-data',views.FetchAWSCostView.as_view(),name='cost-data'),#2
    path('api/studio/rds-data/', views.RDSData.as_view(), name='rds_data'),#3 done
    #path('api/studio/secrets-data/', views.Secrets_data.as_view(), name='secrets-data'),#4
    path('api/studio/s3-detail-data/', views.Get_S3_Data.as_view(), name='s3-detail-data'),#5 done
    path('api/studio/ecr-detail-data/', views.Get_ECR_Data.as_view(), name='ecr-detail-data'),#6 done
    path('api/studio/lambda-metrics/', views.LambdaMetricsView.as_view(), name='lambda_metrics-data'),#7 done
    path('api/studio/vpc-data/',views.Get_VPCData.as_view(), name='VPC-detail-data'),#8 done
    path('api/studio/ecs-data/',views.Get_ECS_Data.as_view(),name='ecs-detailed-data'),#9 done
    path('api/studio/loadbalancer-data/',views.Get_load_balancer_Data.as_view(),name='loadbalancer-detailed-data'),#10 done
    #path('api/studio/ebs-data/',views.Get_EBS_Data.as_view(),name='ebs-detail-data'),#11
    #path('api/studio/waf-acl-data/',views.Get_WAF_Data.as_view(),name='waf-detail-data'),#12
    path('api/studio/eip-data/',views.Get_Elastic_Ip.as_view(),name='eip-detail-data'),#13 done
    path('api/studio/detail-cost-data/', views.GetTotalBill.as_view(), name='detail-cost-data'),#Bar Chart#14
    #path('api/studio/send_email/',views.Send_cost_Email.as_view(),name='send-mail'),#15 #Email
    path('api/studio/api-gateway-data/',views.Get_APIGateway.as_view(),name='api-gateway'),#16 done
    path('api/studio/snapshot_data/',views.Get_Snapshot_Data.as_view(),name='snapshot_data'),#17 done
    path('api/studio/create_folder/', views.CreateFolder.as_view(),name='create_folder_data'), #18 done
    path('api/studio/dynamoDB_data/',views.Get_DynamoDB_data.as_view(),name='dynamo_db-data')# 19 done
    
]