## Objective
This python program `enroll_account.py` provided under the open-source license to help you with programmatically enroll existing unregistered AWS accounts in to AWS Control Tower. 

### Usage

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

### Additional Information
https://aws.amazon.com/blogs/field-notes/enroll-existing-aws-accounts-into-aws-control-tower/

## License Summary

This sample code is made available under the MIT-0 license. See the LICENSE file.
