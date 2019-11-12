#########################################################################################
# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.               #
# Permission is hereby granted, free of charge, to any person obtaining a copy of this  #
# software and associated documentation files (the "Software"), to deal in the Software #
# without restriction, including without limitation the rights to use, copy, modify,    #
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to    #
# permit persons to whom the Software is furnished to do so.                            #
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,   #
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A         #
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT    #
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION     #
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE        #
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                                #
#########################################################################################

import boto3
import logging
from time import sleep
from random import randint 
import json
import sys
import glob
import argparse

# Find the product Id, provisioning artifact Id of the Service Catalog Product
def get_product_id(af_product_name):
    ''' Query for Product Id of AWS Control Tower Account Factory '''

    try:
        search_list = SC.search_products()['ProductViewSummaries']
    except Exception as e:
        print("Unable to find Product Id: " + str(e))

    for item in search_list:
        if item['Name'] == af_product_name:
          return(item['ProductId'])

def get_provisioning_artifact_id(prod_id):
    ''' Query for Provisioned Artifact Id '''

    try:
        pa_list = SC.describe_product(Id=prod_id)['ProvisioningArtifacts']
    except Exception as e:
        print("Unable to find the Provisioned Artifact Id: " + str(e))
    
    return(pa_list[-1]['Id'])

def generate_provisioned_product_name(data):
    ''' Generate Provisioned product name from data '''

    for i in data:
        if i['Key'] == 'AccountName':
            return('SC-Launch-for-' + i['Value'])

def generate_provisioned_product_email(data):
    ''' Generate Provisioned product name from data '''

    for i in data:
        if i['Key'] == 'AccountEmail':
            return(i['Value'])


def get_provisioned_product_status(prov_prod_name):
    ''' Query and return the Provisioned Product Current Status '''

    try:
        pp_list = SC.scan_provisioned_products()['ProvisionedProducts']
    except Exception as e:
        print("Unable to get provisioned product status: " + str(e))

    for item in pp_list:
        if item['Name'] == prov_prod_name:
            return(item['Status'])
      
def get_new_account_id(data):
    ''' Query Organization and get the AWS account Id '''
    
    new_email_id = generate_provisioned_product_email(data)
    
    try:
        org_list = ORG.list_accounts()['Accounts']
    except Exception as e:
        print('Unable to get the accounts list:' + str(e))

    for acct in org_list:
        if acct['Email'] == new_email_id:
            return(acct['Id'])


def create_stack_set(custom_stack_set_name, custom_template_url, 
                    parameters_keys, master_account_admin_arn, iam_capabilities):
    ''' Create stack set if doesn't exist already '''

    stack_exists = False
    result = {'STATUS':'FAIL'}

    try:
        cft_ss_list = CFT.list_stack_sets()['Summaries']
    except Exception as e:
                print('Unable to find the stacks' + str(e))

    for stack in cft_ss_list:
        if stack['Status'] == 'ACTIVE' and stack['StackSetName'] == custom_stack_set_name:
            stack_exists = True

    if not stack_exists:
        try:
            print('Creating stack set name'.format(custom_stack_set_name))
            result = CFT.create_stack_set(StackSetName = custom_stack_set_name, \
                            TemplateURL = custom_template_url, Parameters = parameters_keys, \
                            AdministrationRoleARN = master_account_admin_arn, \
                            ExecutionRoleName ='AWSControlTowerExecution', Capabilities=iam_capabilities)
        except Exception as e:
            print('Unable to create a stack set:' + str(e))

    return(result)


def create_stack_instance(custom_stack_set_name, new_account_id, region):
    ''' Create Stack instance in an existing StackSet'''

    try:
        print('Creating stack instance in account'.format(new_account_id))
        result = CFT.create_stack_instances(StackSetName=custom_stack_set_name, \
                                    Accounts=[new_account_id], Regions=[region])
    except Exception as e:
        print('Failed to create a stack: ' + str(e))

    return(result)


def provision_sc_product(prod_id, pa_id, prov_prod_name, input_params, RANDOM):
    ''' Provision the Service Catalog Product '''

    try:
        result = SC.provision_product(ProductId = prod_id, ProvisioningArtifactId = pa_id, \
                        ProvisionedProductName = prov_prod_name, \
                        ProvisioningParameters = input_params, 
                        ProvisionToken = RANDOM)
    except Exception as e:
        print('SC product provisioning failed: ' + str(e))

    return(result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=
                                     'Provision new AWS account using Account Factory product in AWS Service Catalog..'
                                     'Usage example: python provision_account_customizations.py [--semail email-id] [--sfname name] [--slname name] [--ou name] [--aname name] [--aemail email-id]')
    parser.add_argument("-s", "--semail", type=str, help="SSOUserEmail")
    parser.add_argument("-i", "--sfname", type=str, default="alias", help="SSOUserFirstName")
    parser.add_argument("-l", "--slname", type=str, default="suffix", help="SSOUserLastName")
    parser.add_argument("-o", "--ou", type=str, default="ouname", help="ManagedOrganizationalUnit")
    parser.add_argument("-a", "--aname", type=str, default="acountname", help="AccountName")
    parser.add_argument("-e", "--aemail", type=str, help="AWS account email id")
    parser.add_argument("-p", "--params", type=str, help="Parameter file with account information")
    parser.add_argument("-r", "--region", type=str, default="us-west-1", help="Region name")
    parser.add_argument("-ct", "--curl", type=str, default="https://vinjak-outbox.s3.us-east-2.amazonaws.com/automation-exec-role.yaml", help="URL for Custom CFT template")
    parser.add_argument("-cn", "--cname", type=str, default="TerraFormExecutionRoleStackSet", help="Role in Master account")

    args = parser.parse_args()
    aws_account_email = args.aemail
    sso_email = args.semail if args.semail else args.aemail

    if args.params is None and aws_account_email is None:
        sys.exit('Param file or Valid Account Email Required : {}'.format(aws_account_email))

    sso_firstname = args.sfname
    sso_lastname = args.slname
    ou_name = args.ou
    aws_account_name = args.aname
    
    param_file = args.params
    region_name = args.region
    custom_template_url = args.curl
    custom_stack_set_name = args.cname

    region = 'eu-west-1'
    # boto3.setup_default_session(profile_name = 'ctire-master', region_name = region)
    af_product_name = 'AWS Control Tower Account Factory'
    sleep_time = 30
    pp_status = 'UNKNOWN'

    SC = boto3.client('servicecatalog')
    CFT = boto3.client('cloudformation')
    STS = boto3.client('sts')
    ORG = boto3.client('organizations')

    LOGGER = logging.getLogger()
    LOGGER.setLevel(logging.INFO)

    RANDOM = str(randint(1000000000000, 9999999999999))

    iam_capabilities = ['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM', 'CAPABILITY_AUTO_EXPAND']
    custom_stack_set_name = 'TerraFormExecutionRoleStackSet'
    master_account_id = STS.get_caller_identity()['Account']

    parameters_keys = [
        {'ParameterKey': 'AdminAccountId' , 'ParameterValue': master_account_id },
        {'ParameterKey': 'AdminRoleName', 'ParameterValue': 'TerraformAutomationAdministrationRole' },
        {'ParameterKey': 'ExecutionRoleName', 'ParameterValue': 'TerraformExecutionRole'},
        {'ParameterKey': 'SessionDurationInSecs', 'ParameterValue': '14400'}
    ]

    email_id = STS.get_caller_identity()['UserId'].split(':')[-1]
    master_account_admin_arn = 'arn:aws:iam::' + master_account_id + \
                            ':role/service-role/AWSControlTowerStackSetRole'

    print('Executing on AWS Account: {}, {}'.format(master_account_id, email_id))


    if param_file:
        for file in glob.glob(param_file):
            with open(file) as json_file:
                data = json.load(json_file)
    else:
        data = [
            {'Value': sso_email, 'Key': 'SSOUserEmail'}, 
            {'Value': sso_firstname, 'Key': 'SSOUserFirstName'}, 
            {'Value': sso_lastname, 'Key': 'SSOUserLastName'}, 
            {'Value': ou_name, 'Key': 'ManagedOrganizationalUnit'}, 
            {'Value': aws_account_name, 'Key': 'AccountName'}, 
            {'Value': aws_account_email, 'Key': 'AccountEmail'}
            ]
    
    print(data)

    # Get the Product Id of the AWS Control Tower Account Factory 
    prod_id = get_product_id(af_product_name)
    # Get the Provisioning Artifact Id of the AWS Control Tower Account Factory 
    pa_id = get_provisioning_artifact_id(prod_id)
    print('Found Product ID: {}, {}'.format(prod_id, pa_id))

    # Create a new AWS account using provisioning product    
    prov_prod_name = generate_provisioned_product_name(data)
    provision_result = provision_sc_product(prod_id, pa_id, prov_prod_name, data, RANDOM)

    # Wait until the Service Catalog Product Provisioning Completes
    while pp_status != 'AVAILABLE':
        print('Provisions Product status: {}. Waiting: {}s'.format(pp_status, sleep_time))
        sleep(sleep_time)
        pp_status = get_provisioned_product_status(prov_prod_name)

    print('Status changed to {}. Ready to trigger custom Cloudformation stack'.format(pp_status))

    # Query AWS Organization for email and obtain the new AWS account id
    new_account_id = get_new_account_id(data)

    print('Creating the Portfolio StackSet')

    # Create the Stackset if it doesn't exist. Provision new Custom Stack
    create_stack_set(custom_stack_set_name, custom_template_url, 
                    parameters_keys, master_account_admin_arn, iam_capabilities)
            
    print('Sleeping {} sec'.format(sleep_time))

    sleep(sleep_time)

    # Add Stack Instance in to an existing Stack
    create_stack_instance(custom_stack_set_name, new_account_id, region)
