# AWS Attack Simulation and Detection Lab:

<img width="1024" height="1024" alt="ChatGPT Image Oct 16, 2025, 12_21_32 AM" src="https://github.com/user-attachments/assets/f54b5f15-3517-4176-b239-12b721f27819" />

--------

#### 1. This repo would contain all 17 AWS attack related scenarios present there at [soc-labs](https://www.soc-labs.top/en/detection)
#### 2. More fine tuning (like adding time based threshold) of the Sigma rules will be done soon too. [link](https://micahbabinski.medium.com/dive-into-sigma-correlation-rules-d5df3f0a12f5)
#### 3. More to Come: Like 
  - [Stratus Red Team](https://stratus-red-team.cloud/attack-techniques/list/) by [@datadoghq](https://x.com/datadoghq) Attack Simulation Detection.
  - [Hacking The Cloud - AWS](https://hackingthe.cloud/aws/avoiding-detection/steal-keys-undetected/) by [@HackingthCloud](https://x.com/HackingthCloud) Attack Simulation Detection.
  - [cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat) by [@RhinoSecurity](https://x.com/RhinoSecurity) Attack Simulation Detection.
  - [Permiso Security Blogs](https://permiso.io/blog) Attack Simulation Detection.

### _<ins>Details behind the logic of creating queries would be added soon!</ins>_

### NOTE:
Usage of quotation is really important while creating detection based on AWS API calls. \
See this example: [no. 17](https://github.com/reveng007/AWS_Attack_Detection_soclabs/blob/main/Queries/17.md)

## Sceanrios based on Different AWS Services:

1. AWS S3
2. AWS EC2
3. AWS Secrets Manager
4. AWS SSM
5. AWS DNS query logs
6. AWS Cloud Trail
7. AWS Management Event Logging
8. AWS VPC Flow Logs
9. AWS SES
10. AWS Security Group
11. AWS AMI instance
12. AWS IAM
13. AWS KMS - For Ransomware detection scenarios.

## Scenarios:

| no. | Scenario | Objective | Detection Query (Sigma) | 
| -- | -------- | -------- | ---- |
| 1. | AWS Delete DNS query logs | Detect the deletion of Route 53 DNS resolver query logs in AWS environments | [link](https://github.com/reveng007/AWS_Attack_Detection_soclabs/blob/main/Queries/1.md) |
| 2. | AWS EC2 Windows Instance Password Data Retrieval | Write detection rules to identify password data retrieval activities targeting Windows EC2 instances in an AWS environment, with a focus on `ec2:GetPasswordData` API call events. | [link](https://github.com/reveng007/AWS_Attack_Detection_soclabs/blob/main/Queries/2.md) |
| 3. | EC2 Credential Exfiltration – EC2 Account Credentials Used by Another AWS Account | Identify all API operations initiated with EC2 instance credentials where the credential’s originating account does not match the account where the API call occurs. | [link](https://github.com/reveng007/AWS_Attack_Detection_soclabs/blob/main/Queries/3.md) |
| 4. | Retrieving a High Number of AWS Secrets Manager Secrets | Write detection rules to identify abnormal Secrets Manager secret retrieval activities. Focus on suspicious behavior patterns related to Secrets Manager. | [link](https://github.com/reveng007/AWS_Attack_Detection_soclabs/blob/main/Queries/4.md) |
| 5. | Retrieve And Decrypt SSM Parameters | Write detection rules to identify suspicious bulk decryption of `SecureString` parameters. When a request sets the `withDecryption` parameter to `true`, it indicates an attempt to retrieve parameter plaintext. Focus on operations that decrypt multiple SecureString parameters within a short time window to identify potential sensitive information leakage risks. | [link](https://github.com/reveng007/AWS_Attack_Detection_soclabs/blob/main/Queries/5.md) |
| 6. | AWS Deletes a trail | Write detection rules based on logs to identify API calls that delete a Trail. | [link](https://github.com/reveng007/AWS_Attack_Detection_soclabs/blob/main/Queries/6.md) |
| 7. | Disabling Management Event Logging via Event Selector | Write a detection rule to identify calls to the `PutEventSelectors` API. | [link](https://github.com/reveng007/AWS_Attack_Detection_soclabs/blob/main/Queries/7.md) |
| 8. | CloudTrail Logs Impairment Through S3 Lifecycle Rule | Write a rule to identify log entries where the S3 bucket lifecycle policy is set to 1 day. | [link](https://github.com/reveng007/AWS_Attack_Detection_soclabs/blob/main/Queries/8.md) |
| 9. | Stop CloudTrail Trail | Detect events where CloudTrail logging has been stopped. | [link](https://github.com/reveng007/AWS_Attack_Simulation_Detection_Lab/blob/main/Queries/9.md) |
| 10. | AWS Remove VPC Flow Logs | Detect API calls that delete VPC Flow Log configurations and identify key operational events that may disrupt network traffic monitoring. | [link](https://github.com/reveng007/AWS_Attack_Simulation_Detection_Lab/blob/main/Queries/10.md) |
| 11. | Download EC2 Instance User Data | Write detection rules to identify behavior where EC2 instance user data is accessed via APIs, with particular attention to abnormal operations involving multiple user data retrievals within a short time frame. | [link](https://github.com/reveng007/AWS_Attack_Simulation_Detection_Lab/blob/main/Queries/11.md) |
| 12. | Enumerate SES Information Activities | Develop detection rules to identify SES enumeration activities | [link](https://github.com/reveng007/AWS_Attack_Simulation_Detection_Lab/blob/main/Queries/12.md) |
| 13. | Bulk Remote Sessions Across Multiple Instances via SSM StartSession | Write a detection rule to identify bulk SSM StartSession requests targeting multiple EC2 instances within a short timeframe. | [link](https://github.com/reveng007/AWS_Attack_Simulation_Detection_Lab/blob/main/Queries/13.md) |
| 14. | AWS Security Group Public Exposure of SSH Port 22 | Write a detection rule to identify instances where the AuthorizeSecurityGroupIngress CloudTrail event is used to allow access to security group port 22 from unknown external IPs or from 0.0.0.0/0. | [link](https://github.com/reveng007/AWS_Attack_Simulation_Detection_Lab/blob/main/Queries/14.md) |
| 15. | Data Theft via Shared AMI | Write detection rules to identify behaviors where AMIs are shared with other accounts. | [link](https://github.com/reveng007/AWS_Attack_Simulation_Detection_Lab/blob/main/Queries/15.md) |
| 16. | Data Theft via Shared S3 Buckets | Write detection rules to identify suspicious authorization actions targeting S3 bucket policies. | [link](https://github.com/reveng007/AWS_Attack_Simulation_Detection_Lab/blob/main/Queries/16.md) |
| 17. | AWS IAM User Logged into Console Without MFA | Write a detection rule to identify IAM user login events to the AWS Console that occurred without MFA. | [link](https://github.com/reveng007/AWS_Attack_Simulation_Detection_Lab/blob/main/Queries/17.md) |

## Similar work done previously:
1. [AWS-Threat-Simulation-and-Detection](https://github.com/sbasu7241/AWS-Threat-Simulation-and-Detection) by [@SoumyadeepBas12](https://x.com/SoumyadeepBas12)
2. [FalconFriday — Detecting realistic AWS cloud-attacks using Azure Sentinel](https://medium.com/falconforce/falconfriday-detecting-realistic-aws-cloud-attacks-using-azure-sentinel-0xff1c-b62fd45c87dc) by [@FalconForceTeam](https://x.com/FalconForceTeam)
3. [Permiso Security Blogs](https://permiso.io/blog) by [@permisosecurity](https://x.com/permisosecurity)

