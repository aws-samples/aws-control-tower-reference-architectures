<h1>Enroll existing AWS accounts in to AWS Control Tower</h1>

Since the launch of AWS Control Tower, customers have been asking for the ability to deploy AWS Control Tower in their existing AWS Organizations and to extend governance to those accounts in their organization.

We are happy to announce that you can now deploy AWS Control Tower in your existing AWS Organizations. The accounts that you launched before deploying AWS Control Tower, what we refer to as unenrolled accounts, remain outside AWS Control Towers’ governance by default. These accounts must be enrolled in the AWS Control Tower explicitly.

When you enroll an account into AWS Control Tower, it deploys baselines and additional guardrails to enable continuous governance on your existing AWS accounts. However, you must perform proper due diligence before enrolling in an account. Refer to the Things to Consider section below for additional information.

In this blog, I show you how to enroll your existing AWS accounts and accounts within the unregistered OUs in your AWS organization under AWS Control Tower programmatically.
<h2>Background</h2>
Here’s a quick review of some terms used in this post:
<ul>
 	<li>The Python script provided in this post. This script interacts with multiple AWS services, to identify, validate, and enroll the existing unmanaged accounts into AWS Control Tower.</li>
 	<li>An unregistered organizational unit (OU) is created through AWS Organizations. AWS Control Tower does not manage this OU.</li>
 	<li>An unenrolled account is an existing AWS account that was created outside of AWS Control Tower. It is not managed by AWS Control Tower.</li>
 	<li>A registered organizational unit (OU) is an OU that was created in the AWS Control Tower service. It is managed by AWS Control Tower.</li>
 	<li>When an OU is registered with AWS Control Tower, it means that specific baselines and guardrails are applied to that OU and all of its accounts.</li>
 	<li>An <a href="https://docs.aws.amazon.com/controltower/latest/userguide/account-factory.html">AWS Account Factory account</a> is an AWS account provisioned using account factory in AWS Control Tower.</li>
 	<li>Amazon Elastic Compute Cloud (<a href="https://aws.amazon.com/ec2/">Amazon EC2</a>) is a web service that provides secure, resizable compute capacity in the cloud.</li>
 	<li><a href="https://aws.amazon.com/servicecatalog">AWS Service Catalog</a> allows you to centrally manage commonly deployed IT services. In the context of this blog, account factory uses AWS Service Catalog to provision new AWS accounts.</li>
 	<li><a href="https://aws.amazon.com/organizations/">AWS Organizations</a> helps you centrally govern your environment as you grow and scale your workloads on AWS.</li>
 	<li><a href="https://aws.amazon.com/organizations/">AWS Single Sign-On</a> (SSO) makes it easy to centrally manage access to multiple AWS accounts. It also provides users with single sign-on access to all their assigned accounts from one place.</li>
</ul>
<h2>Things to Consider</h2>
<a href="https://docs.aws.amazon.com/controltower/latest/userguide/enroll-account.html">Enrolling an existing AWS account into AWS Control Tower</a> involves moving an unenrolled account into a registered OU. The Python script provided in this blog allows you to enroll your existing AWS accounts into AWS Control Tower. However, it doesn’t have much context around what resources are running on these accounts. It assumes that you validated the account services before running this script to enroll the account.

Some guidelines to check before you decide to enroll the accounts into AWS Control Tower.
<ol>
 	<li>An <code>AWSControlTowerExecution</code> role must be created in each account. If you are using the script provided in this solution, it creates the role automatically for you.</li>
 	<li>If you have a default VPC in the account, the enrollment process tries to delete it. If any resources are present in the VPC, the account enrollment fails.</li>
 	<li>If AWS Config was ever enabled on the account you enroll, a <code>default</code> config recorder and delivery channel were created. <a href="https://docs.aws.amazon.com/config/latest/developerguide/stop-start-recorder.html">Delete the configuration-recorder</a> and <a href="https://docs.aws.amazon.com/config/latest/developerguide/stop-start-recorder.html">delivery channel</a> for the account enrollment to work.</li>
 	<li>Start with enrolling the dev/staging accounts to get a better understanding of any dependencies or impact of enrolling the accounts in your environment.</li>
 	<li>Create a new Organizational Unit in AWS Control Tower and do not enable any additional guardrails until you enroll in the accounts. You can then enable guardrails one by one to check the impact of the guardrails in your environment.</li>
</ol>
<h2>Prerequisites</h2>
Before you enroll your existing AWS account in to AWS Control Tower, check the prerequisites from <a href="https://docs.aws.amazon.com/controltower/latest/userguide/enroll-account.html">AWS Control Tower documentation</a>.

This Python script provided part of this blog, supports enrolling all accounts with in an unregistered OU in to AWS Control Tower. The script also supports enrolling a single account using both email address or account-id of an unenrolled account. Following are a few additional points to be aware of about this solution.
<ul>
 	<li><a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-enable-trusted-access.html">Enable trust access with AWS Organizations</a> for <strong>AWS CloudFormation StackSets</strong>.</li>
 	<li>The email address associated with the AWS account is used as AWS SSO user name with default First Name <strong>Admin</strong> and Last Name <strong>User</strong>.</li>
 	<li>Accounts that are in the root of the AWS Organizations can be enrolled one at a time only.</li>
 	<li>While enrolling an entire OU using this script, the <code>AWSControlTowerExecution</code> role is automatically created on all the accounts on this OU.</li>
 	<li>You can enroll a single account with in an unregistered OU using the script. It checks for <code>AWSControlTowerExecution</code> role on the account. If the role doesn’t exist, the role is created on all accounts within the OU.</li>
 	<li>By default, you are not allowed to enroll an account that is in the root of the organization. You must pass an additional flag to launch a role creation stack set across the organization</li>
 	<li>While enrolling a single account that is in the root of the organization, it prompts for additional flag to launch role creation stack set across the organization.</li>
 	<li>The script uses CloudFormation Stack Set <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-getting-started-create.html#stacksets-orgs-associate-stackset-with-org">Service-Managed Permissions</a> to create the <code>AWSControlTowerExecution</code> role in the unenrolled accounts.</li>
</ul>
<h2>How it works</h2>
The following diagram shows the overview of the solution.

<img class="aligncenter wp-image-142 " src="https://d2908q01vomqb2.cloudfront.net/54ceb91256e8190e474aa752a6e0650a2df5ba37/2020/04/21/enroll_account_architecture-1024x603.png" alt="Account Enrollment" width="579" height="341" />
<ol>
 	<li>In your AWS Control Tower environment, access an Amazon EC2 instance running in the master account of the AWS Control Tower home Region.</li>
 	<li>Get temporary credentials for <code>AWSAdministratorAccess</code> from AWS SSO login screen</li>
 	<li>Download and execute the <code>enroll_script.py</code> script</li>
 	<li>The script creates the <code>AWSControlTowerExecution</code> role on the target account using <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-manage-auto-deployment.html">Automatic Deployments for a Stack Set</a> feature.</li>
 	<li>On successful validation of role and organizational units that are given as input, the script launches a new product in Account Factory.</li>
 	<li>The enrollment process creates an AWS SSO user using the same email address as the AWS account.</li>
</ol>
<h3>Setting up the environment</h3>
It takes up to 30 minutes to enroll each AWS account in to AWS Control Tower. The accounts can be enrolled only one at a time. Depending on number of accounts that you are migrating, you must keep the session open long enough. In this section, you see one way of keeping these long running jobs uninterrupted using Amazon EC2 using the <code>screen</code> tool.

Optionally you may use your own compute environment where the session timeouts can be handled. If you go with your own environment, make sure you have <code>python3</code>, <code>screen</code> and a latest version of <code>boto3</code> installed.

1. Prepare your compute environment:
<ul>
 	<li>Log in to your AWS Control Tower with AWSAdministratorAccess role.</li>
 	<li>Switch to the Region where you deployed your AWS Control Tower if needed.</li>
 	<li>If necessary, launch a VPC using the <a href="https://console.aws.amazon.com/cloudformation#/stacks/new?stackName=NewVPCforAccountEnroll&amp;templateURL=https://aws-service-catalog-reference-architectures.s3.amazonaws.com/vpc/sc-vpc-ra.json">stack here</a> and wait for the stack to COMPLETE.</li>
 	<li>If necessary, launch an Amazon EC2 instance using the <a href="https://console.aws.amazon.com/cloudformation#/stacks/new?stackName=EC2InstanceForSAM&amp;templateURL=https://marketplace-sa-resources.s3.amazonaws.com/ct-blogs-content/CT-ec2-scriptrunner.json">stack here</a>. Wait for the stack to COMPLETE.</li>
 	<li>While you are on master account, <a href="https://docs.aws.amazon.com/singlesignon/latest/userguide/howtosessionduration.html">increase the session time duration</a> for AWS SSO as needed. Default is 1 hour and maximum is 12 hours.</li>
</ul>
2. Connect to the compute environment (one-way):
<ul>
 	<li>Go to the <a href="https://console.aws.amazon.com/ec2/">EC2 Dashboard</a>, and choose <strong>Running Instances</strong>.</li>
 	<li>Select the EC2 instance that you just created and choose <strong>Connect</strong>.</li>
 	<li>In <strong>Connect to your instance</strong> screen, under <strong>Connection method</strong>, choose <strong>EC2InstanceConnect (browser-based SSH connection)</strong> and <strong>Connect</strong> to open a session.</li>
 	<li>Go to AWS Single Sign-On page in your browser. Click on your master account.</li>
 	<li>Choose <strong>command line or programmatic access</strong> next to <strong>AWSAdministratorAccess</strong>.</li>
 	<li>From <strong>Option 1</strong> copy the environment variables and paste them in to your EC2 terminal screen in step 5 below.</li>
</ul>
3. Install required packages and variables. You may skip this step, if you used the stack provided in step-1 to launch a new EC2 instance:
<ul>
 	<li>Install <code>python3</code> and <code>boto3</code> on your EC2 instance. You may have to update boto3, if you use your own environment.</li>
</ul>
<pre style="padding-left: 40px;"><code class="lang-bash"><strong>$ sudo yum install python3 -y 
$ sudo pip3 install boto3
$ pip3 show boto3</strong>
Name: boto3
Version: 1.12.39
</code></pre>
<ul>
 	<li>Change to home directory and download the <code>enroll_account.py</code> script.</li>
</ul>
<pre style="padding-left: 40px;"><code class="lang-bash"><strong>$ cd ~
$ wget https://marketplace-sa-resources.s3.amazonaws.com/ct-blogs-content/enroll_account.py
</strong></code></pre>
<ul>
 	<li>Set up your home Region on your EC2 terminal.</li>
</ul>
<pre style="padding-left: 40px;"><code class="lang-bash">export AWS_DEFAULT_REGION=&lt;AWSControlTower-Home-Region&gt;</code></pre>
4. Start a <code>screen</code> session in daemon mode. If your session gets timed out, you can open a new session and attach back to the screen.
<pre style="padding-left: 40px;"><code class="lang-bash"><strong>$ screen -dmS SAM</strong>
<strong>$ screen -ls</strong>
There is a screen on:
        585.SAM (Detached)
1 Socket in /var/run/screen/S-ssm-user.
<strong>$ screen -dr 585.SAM
</strong></code></pre>
5. On the screen terminal, paste the environmental variable that you noted down in step 2.

6. Identify the accounts or the unregistered OUs to migrate and run the Python script provide with below mentioned options.
<ul>
 	<li>Python script usage:</li>
</ul>
<pre style="padding-left: 40px;"><code class="lang-bash"><strong>usage: enroll_account.py -o -u|-e|-i -c
</strong>
Enroll existing accounts to AWS Control Tower.

optional arguments:
  -h, --help            show this help message and exit
  -o OU, --ou OU        Target Registered OU
  -u UNOU, --unou UNOU  Origin UnRegistered OU
  -e EMAIL, --email EMAIL
                        AWS account email address to enroll in to AWS Control Tower
  -i AID, --aid AID     AWS account ID to enroll in to AWS Control Tower
  -c, --create_role     Create Roles on Root Level
</code></pre>
<ul>
 	<li>Enroll all the accounts from an unregistered OU to a registered OU</li>
</ul>
<pre><code class="lang-bash">$ python3 enroll_account.py -o MigrateToRegisteredOU -u FromUnregisteredOU 
Creating cross-account role on 222233334444, wait 30 sec: RUNNING 
Executing on AWS Account: 570395911111, USER+SCADMINT1@amazon.com 
Launching Enroll-Account-vinjak-unmgd3 
Status: UNDER_CHANGE. Waiting for 6.0 min to check back the Status 
Status: UNDER_CHANGE. Waiting for 5.0 min to check back the Status 
. . 
Status: UNDER_CHANGE. Waiting for 1.0 min to check back the Status 
SUCCESS: 111122223333 updated Launching Enroll-Account-vinjakSCchild 
Status: UNDER_CHANGE. Waiting for 6.0 min to check back the Status 
ERROR: 444455556666 
Launching Enroll-Account-Vinjak-Unmgd2 
Status: UNDER_CHANGE. Waiting for 6.0 min to check back the Status 
. . 
Status: UNDER_CHANGE. Waiting for 1.0 min to check back the Status 
SUCCESS: 777788889999 updated</code></pre>
<ul>
 	<li>Use AWS account ID to enroll a single account that is part of an unregistered OU.</li>
</ul>
<pre style="padding-left: 40px;"><code class="lang-bash">$ python3 enroll_account.py -o MigrateToRegisteredOU -i 111122223333</code></pre>
<ul>
 	<li>Use AWS account email address to enroll a single account from an unregistered OU.</li>
</ul>
<pre style="padding-left: 40px;"><code class="lang-bash">$ python3 enroll_account.py -o MigrateToRegisteredOU -e JohnDoe+outside-ct-ou@amazon.com</code></pre>
You are not allowed by default to enroll an AWS account that is in the root of the organization. The script checks for the <code>AWSControlTowerExecution</code> role in the account. If role doesn’t exist, you are prompted to use <code>-c | --create-role</code>. Using <code>-c</code> flag adds the stack instance to the parent organization root. Which means an <code>AWSControlTowerExecution</code> role is created in all the accounts with in the organization.

<strong>Note:</strong> Ensure installing <code>AWSControlTowerExecution</code> role in all your accounts in the organization, is acceptable in your organization before using <code>-c</code> flag.

If you are unsure about this, follow the instructions in the <a href="https://docs.aws.amazon.com/controltower/latest/userguide/enroll-account.html">documentation</a> and create the <code>AWSControlTowerExecution</code> role manually in each account you want to migrate. Rerun the script.
<ul>
 	<li>Use AWS account ID to enroll a single account that is in root OU (<em>need -c flag</em>).</li>
</ul>
<pre style="padding-left: 40px;"><code class="lang-bash">$ python3 enroll_account.py -o MigrateToRegisteredOU -i 111122223333 -c</code></pre>
<ul>
 	<li>Use AWS account email address to enroll a single account that is in root OU (<em>need -c flag)</em>.</li>
</ul>
<pre style="padding-left: 40px;"><code class="lang-bash">$ python3 enroll_account.py -o MigrateToRegisteredOU -e JohnDoe+in-the-root@amazon.com -c</code></pre>
<h2>Cleanup steps</h2>
On successful completion of enrolling all the accounts into your AWS Control Tower environment, you could clean up the below resources used for this solution.

If you have used templates provided in this blog to launch VPC and EC2 instance, delete the EC2 CloudFormation stack and then VPC template.
<h2>Conclusion</h2>
Now you can deploy AWS Control Tower in an existing AWS Organization. In this post, I have shown you how to enroll your existing AWS accounts in your AWS Organization into AWS Control Tower environment. By using the procedure in this post, you can programmatically enroll a single account or all the accounts within an organizational unit into an AWS Control Tower environment.

Now that governance has been extended to these accounts, you can also provision new AWS accounts in just a few clicks and have your accounts conform to your company-wide policies.

Additionally, you can use <a href="https://aws.amazon.com/solutions/customizations-for-aws-control-tower/">Customizations for AWS Control Tower</a> to apply custom templates and policies to your accounts. With custom templates, you can deploy new resources or apply additional custom policies to the existing and new accounts. This solution integrates with AWS Control Tower lifecycle events to ensure that resource deployments stay in sync with your landing zone. For example, when a new account is created using the AWS Control Tower account factory, the solution ensures that all resources attached to the account's OUs are automatically deployed.


## License Summary

This sample code is made available under the MIT-0 license. See the LICENSE file.
