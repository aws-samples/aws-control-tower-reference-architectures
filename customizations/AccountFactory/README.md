This python script uses AWS Service Catalog APIs to detect the `AWS Control Tower Account Factory`, and provision a new account based of the values passed through the input file `params.json`. If the input file is not passed, looks for the below command line flags for the required information.

``` python
usage: provision_account_customizations.py [-h] [-s SEMAIL] [-i SFNAME]
                                           [-l SLNAME] [-o OU] [-a ANAME]
                                           [-e AEMAIL] [-p PARAMS] [-r REGION]
                                           [-ct CURL] [-cn CNAME]

Provision new AWS account using Account Factory product in AWS Service Catalog..

USAGE : python provision_account_customizations.py [--semail email-id] [--sfname name] [--slname name] [--ou name] [--aname name] [--aemail email-id]

optional arguments:
  -h, --help            show this help message and exit
  -s SEMAIL, --semail SEMAIL
                        SSOUserEmail
  -i SFNAME, --sfname SFNAME
                        SSOUserFirstName
  -l SLNAME, --slname SLNAME
                        SSOUserLastName
  -o OU, --ou OU        ManagedOrganizationalUnit
  -a ANAME, --aname ANAME
                        AccountName
  -e AEMAIL, --aemail AEMAIL
                        AWS account email id
  -p PARAMS, --params PARAMS
                        Parameter file with account information
  -r REGION, --region REGION
                        Region name
  -ct CURL, --curl CURL
                        URL for Custom CFT template
  -cn CNAME, --cname CNAME
                        Role in Master account
```
