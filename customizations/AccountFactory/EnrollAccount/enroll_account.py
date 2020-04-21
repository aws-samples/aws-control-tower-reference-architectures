#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

import logging
from time import sleep
from random import randint
import sys
import argparse
from re import match, sub
import boto3

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
HANDLER = logging.StreamHandler(sys.stdout)
HANDLER.setLevel(logging.DEBUG)
LOGGER.addHandler(HANDLER)

def error_and_exit(error_msg='ERROR'):
    '''Throw error and exit'''

    LOGGER.error(error_msg)
    sys.exit(1)

def error_and_continue(error_msg='ERROR'):
    '''Throw error and contiune'''

    LOGGER.error(error_msg)

def get_product_id():
    ''' Find the Product Id of AWS Control Tower Account Factory '''

    filters = {'Owner': ['AWS Control Tower']}
    af_product_name = 'AWS Control Tower Account Factory'
    key = 'ProductViewSummary'
    output = None

    try:
        search_list = SC.search_products_as_admin(Filters=filters)['ProductViewDetails']
    except Exception as exe:
        error_and_exit('Unable to find Product Id: ' + str(exe))

    for item in search_list:
        if key in item:
            if item[key]['Name'] == af_product_name:
                output = item[key]['ProductId']
                break
        else:
            LOGGER.warning('Unexepected output recieved. Skipping: %s', item)

    if not output:
        error_and_exit('Unable to find Product Id: ' + str(search_list))

    return output

def get_provisioning_artifact_id(prod_id):
    ''' Query for Provisioned Artifact Id '''

    pa_list = list()

    try:
        pa_list = SC.describe_product_as_admin(Id=prod_id)['ProvisioningArtifactSummaries']
    except Exception as exe:
        error_and_exit("Unable to find the Provisioned Artifact Id: " + str(exe))

    if len(pa_list) > 0:
        output = pa_list[-1]['Id']
    else:
        error_and_exit("Unable to find the Provisioned Artifact Id: " + str(pa_list))

    return output

def get_provisioned_product_id(data):
    ''' Generate Provisioned product name from the data input '''

    pp_id = ''
    for item in data:
        if item['Key'] == 'AccountEmail':
            email_id = item['Value']
            (account_id, account_name, account_email) = get_account_mapping(account_email=email_id)
            (acct_map, error_list, transit_list) = get_provisioned_product_list()
            pp_id = acct_map[account_id]

    return pp_id

def get_provisioned_product_status(prov_prod_name):
    ''' Query and return the Provisioned Product Current Status '''

    output = None
    pp_list = search_provisioned_product_full_list()

    for item in pp_list:
        if item['Name'] == prov_prod_name:
            output = item['Status']
            break

    if not output:
        error_and_exit('Unable to find any provisioned products: ' + str(prov_prod_name))

    return output

def provision_sc_product(prod_id, pa_id, prov_prod_name, input_params):
    ''' Provision the Service Catalog Product '''

    result = None
    print('Launching {}'.format(prov_prod_name))
    try:
        result = SC.provision_product(ProductId=prod_id, ProvisioningArtifactId=pa_id, \
                        ProvisionedProductName=prov_prod_name, \
                        ProvisioningParameters=input_params, \
                        ProvisionToken=str(randint(1000000000000, 9999999999999)))
    except Exception as exe:
        LOGGER.error('SC product provisioning failed: %s', str(exe))

    return result

def search_provisioned_product_full_list():
    '''Get complete list of provisioned products'''

    pp_list = list()
    filters = {"Key" : "Account", "Value" : "self"}

    try:
        pp_dict = SC.search_provisioned_products(AccessLevelFilter=filters)
        pp_list = pp_dict['ProvisionedProducts']
    except Exception as exe:
        error_and_exit('Failed to get provisioned products list. ' + str(exe))

    while 'NextPageToken' in pp_dict:
        next_token = pp_dict['NextPageToken']
        try:
            pp_dict = SC.search_provisioned_products(AccessLevelFilter=filters, \
                                                     PageToken=next_token)
            pp_list += pp_dict['ProvisionedProducts']
        except Exception as exe:
            error_and_exit('Failed to get complete provisioned products list: ' + str(exe))

    return pp_list

def search_provisioned_products():
    '''List the provisioned products that matches the filter'''

    ct_pp_list = list()
    error_list = list()
    transit_list = list()

    pp_list = search_provisioned_product_full_list()

    for item in pp_list:
        if item['Type'] == 'CONTROL_TOWER_ACCOUNT':
            if item['Status'] == 'ERROR':
                error_list.append(item)
            elif item['Status'] == 'UNDER_CHANGE' or item['Status'] == 'PLAN_IN_PROGRESS':
                transit_list.append(item)
            else:
                ct_pp_list.append(item)

    return(ct_pp_list, error_list, transit_list)

def get_provisioned_product_list():
    '''Get list of provisioned products by Account Factory '''

    pp_map = dict()
    error_list = list()
    transit_list = list()

    (search_pp, error_pp, transit_pp) = search_provisioned_products()

    for item in search_pp:
        pp_map[item['PhysicalId']] = item['Id']

    for item in error_pp:
        error_list.append(item['Name'])

    for item in transit_pp:
        transit_list.append(item['Name'])

    return(pp_map, error_list, transit_list)

def generate_provisioned_product_name(data):
    ''' Generate Provisioned product name from data '''

    result = None

    for i in data:
        if i['Key'] == 'AccountName':
            result = 'Enroll-Account-' + sub('[^A-Za-z0-9]+', '-', i['Value'])
            break

    return result

def does_ct_role_exists(account_id):
    '''Return None if role_name doesn't exists in account_id'''

    role_arn = 'arn:aws:iam::' + account_id + ':role/AWSControlTowerExecution'
    session_name = 'session_' + account_id

    try:
        STS.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        result = True
    except Exception:
        result = False

    return result

def does_stack_set_exists(ss_name):
    '''Return True if active StackSet exists'''
    result = False
    ss_list = list()

    try:
        cft_paginator = CFT.get_paginator('list_stack_sets')
        cft_page_iterator = cft_paginator.paginate()
    except Exception as exe:
        LOGGER.error('Unable to list stacksets %s', str(exe))

    for page in cft_page_iterator:
        ss_list += page['Summaries']

    for item in ss_list:
        if item['StackSetName'] == ss_name and item['Status'] == 'ACTIVE':
            result = True

    return result

def add_stack_instance(ss_name, region_name, ou_id):
    '''Add stack instance to the existing StackSet'''

    targets = {'OrganizationalUnitIds': [ou_id]}
    result = {'OperationId': None}
    op_prefer = {'FailureTolerancePercentage': 100}
    output = does_stack_set_exists(ss_name)

    if output:
        try:
            result = CFT.create_stack_instances(StackSetName=ss_name, Regions=[region_name], \
                                    DeploymentTargets=targets, OperationPreferences=op_prefer)
        except Exception as exe:
            raise exe
    else:
        LOGGER.error('StackSet %s does not exist', ss_name)

    return result['OperationId']

def check_ss_status(ss_name, op_id):
    '''Return true on successful deployment of stack instance'''

    try:
        result = CFT.describe_stack_set_operation(StackSetName=ss_name, OperationId=op_id)
    except Exception as exe:
        LOGGER.error('Something went wrong: %s', str(exe))
        result = None

    if result:
        result = result['StackSetOperation']['Status']

    return result

def create_crossaccount_role(account_id, region_name, master_account_id):
    '''Create cross account roles in the migrated ou using service managed auto deployment'''

    ou_id = get_parent_for_account(account_id)
    ss_url = 'https://marketplace-sa-resources.s3.amazonaws.com/ct-blogs-content/AWSControlTowerExecution.yml'
    ss_deploy = {'Enabled':True, 'RetainStacksOnAccountRemoval':True}
    ss_name = 'MyCrossAccountRole-StackSet'
    ss_desc = 'Cross account role creation for stacksets'
    ss_param = [{'ParameterKey':'AdministratorAccountId', 'ParameterValue':master_account_id}]
    ss_perm = 'SERVICE_MANAGED'
    capabilites = ['CAPABILITY_NAMED_IAM']
    result = False
    op_id = None
    ss_status = 'RUNNING'

    try:
        result = CFT.create_stack_set(StackSetName=ss_name, Description=ss_desc, \
                                      TemplateURL=ss_url, Capabilities=capabilites, \
                                      Parameters=ss_param, PermissionModel=ss_perm, \
                                      AutoDeployment=ss_deploy)
    except Exception as exe:
        LOGGER.info(str(exe))
        error_msg = exe.response['Error']['Message']
        if 'StackSet already exists' in error_msg:
            LOGGER.info('StackSet already exists, Adding stack instance')
            result = True
        else:
            raise exe

    if result:
        op_id = add_stack_instance(ss_name, region_name, ou_id)

    #Wait for cross-account role creation completion
    while ss_status in ('RUNNING', 'QUEUED', 'STOPPING'):
        print('Creating cross-account role on {}, wait 30 sec: {}'.format(account_id, ss_status))
        ss_status = check_ss_status(ss_name, op_id)
        sleep(30)

    result = bool(ss_status in ('SUCCEEDED', 'FAILED'))

    return result

def list_org_roots():
    '''List organization roots'''

    value = None
    try:
        root_info = ORG.list_roots()
    except Exception as exe:
        error_and_exit('Script should run on Organization root only: ' + str(exe))

    if 'Roots' in root_info:
        value = root_info['Roots'][0]['Id']
    else:
        error_and_exit('Unable to find valid root: ' + str(root_info))

    return value

def list_all_ou():
    '''List all OUs in an organization'''

    org_info = list()
    root_id = list_org_roots()
    try:
        child_dict = ORG.list_children(ParentId=root_id, ChildType='ORGANIZATIONAL_UNIT')
        child_list = child_dict['Children']
    except Exception as exe:
        error_and_exit('Unable to get children list' + str(exe))

    while 'NextToken' in child_dict:
        next_token = child_dict['NextToken']
        try:
            child_dict = ORG.list_children(ParentId=root_id, \
                        ChildType='ORGANIZATIONAL_UNIT', NextToken=next_token)
            child_list += child_dict['Children']
        except Exception as exe:
            error_and_exit('Unable to get complete children list' + str(exe))

    for item in child_list:
        org_info.append(item['Id'])

    if len(org_info) == 0:
        error_and_exit('No Organizational Units Found')

    return org_info

def get_ou_map():
    '''Generate ou-id to ou-name mapping'''

    ou_list = list_all_ou()
    ou_map = {}

    for ou_item in ou_list:
        try:
            ou_describe = ORG.describe_organizational_unit(OrganizationalUnitId=ou_item)
            ou_info = ou_describe['OrganizationalUnit']
            ou_map[ou_info['Name']] = ou_info['Id']
        except Exception as exe:
            error_and_exit('Unable to get the OU information' + str(exe))

    return ou_map

def get_ou_details(ou_name=None, ou_id=None):
    '''Return OU id to OU name and vice versa'''

    output = None
    ou_map = get_ou_map()

    if ou_name:
        if ou_name in ou_map:
            output = ou_map[ou_name]
        else:
            error_and_exit('Unable to find ' + ou_name + ':' + str(ou_map))
    elif ou_id:
        if ou_id in ou_map.values():
            for ou_item in ou_map:
                if ou_map[ou_item] == ou_id:
                    output = ou_item
        else:
            error_and_exit('Unable to find ' + ou_name + ':' + str(ou_map))
    else:
        error_and_exit('Invalid Input recieved')

    return output

def list_all_accounts():
    '''Return list of all accounts in the organization'''

    output = list()
    retry_count = 0
    throttle_retry = True

    while throttle_retry and retry_count < 5:
        try:
            org_paginator = ORG.get_paginator('list_accounts')
            org_page_iterator = org_paginator.paginate()
            throttle_retry = False
        except Exception as exe:
            error_msg = exe.response['Error']['Code']
            if error_msg == 'ThrottlingException':
                retry_count += 1
            else:
                error_and_exit('Failed to get list of accounts {}'.format(str(exe)))

    for page in org_page_iterator:
        output += page['Accounts']

    return output

def get_account_mapping(account_email=None, account_id=None):
    '''Return account id for a given email and vice versa'''

    account_name = None

    for acct in list_all_accounts():
        if account_email:
            if acct['Email'] == account_email:
                account_id = acct['Id']
                account_name = acct['Name']
                break
        elif account_id:
            if acct['Id'] == account_id:
                account_name = acct['Name']
                account_email = acct['Email']
                break
        else:
            error_and_continue('Invalid input recieved')

    if not account_name:
        error_and_exit('Unable to find an account with in the organization')

    return(account_id, account_name, account_email)

def get_parent_for_account(account_id):
    '''Return the OU id of an account'''

    parent = None
    role_message = 'Use -c|--create_role option to deploy stacks on Root Level'

    try:
        parent = ORG.list_parents(ChildId=account_id)['Parents']
    except Exception as exe:
        raise exe

    if parent:
        if parent[0]['Type'] == 'ROOT':
            if ROOT_LEVEL:
                result = parent[0]['Id']
            else:
                error_and_exit('Account is part of Root.' + role_message)
        elif parent[0]['Type'] == 'ORGANIZATIONAL_UNIT':
            result = parent[0]['Id']
        else:
            error_and_exit('Unknown status: {}'.format(parent))

    return result

def list_of_accounts_in_ou(ou_id):
    '''Return list of accounts, and email-Ids'''

    result = list()
    account_map = dict()

    try:
        result = ORG.list_accounts_for_parent(ParentId=ou_id)['Accounts']
        org_paginator = ORG.get_paginator('list_accounts_for_parent')
        org_page_iterator = org_paginator.paginate(ParentId=ou_id)
    except Exception as exe:
        error_and_exit('Unable to get Accounts list: ' + str(exe))

    for page in org_page_iterator:
        result += page['Accounts']

    for item in result:
        account_map[item['Id']] = {'Email': item['Email'], 'Name': item['Name']}

    return account_map

def get_ou_id(ou_info):
    '''Return ou_id'''

    ou_id = None
    ou_id_matched = bool(match('^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$', ou_info))

    if ou_id_matched:
        ou_id = ou_info
    else:
        ou_id = get_ou_details(ou_name=ou_info)

    return ou_id

def get_accounts_in_ou(unmanaged_ou, managed_ou):
    '''List of accounts in an organizational unit'''

    result = dict()

    ou_id = get_ou_id(unmanaged_ou)
    managed_ou_id = get_ou_id(managed_ou)

    account_map = list_of_accounts_in_ou(ou_id)

    for account in account_map:
        email_id = account_map[account]['Email']
        account_name = account_map[account]['Name']
        result[account] = generate_data(email_id, account_name, managed_ou)

    return result

def generate_data(account_email, account_name, ou_name):
    '''Generate the formatted object'''

    result = [
        {'Key': 'SSOUserEmail', 'Value': account_email},
        {'Key': 'SSOUserFirstName', 'Value': 'Admin'},
        {'Key': 'SSOUserLastName', 'Value': 'User'},
        {'Key': 'AccountName', 'Value': account_name},
        {'Key': 'AccountEmail', 'Value': account_email},
        {'Key': 'ManagedOrganizationalUnit', 'Value': ou_name}
        ]

    return result

def get_account_info(managed_ou, account_email=None, account_id=None):
    '''Generate data file from account_email and account_id'''

    result = {}

    if account_email:
        # check for valid email ID
        (account_id, account_name, account_email) = get_account_mapping(account_email=account_email)
    elif account_id:
        # check for value account ID
        (account_id, account_name, account_email) = get_account_mapping(account_id=account_id)

    result[account_id] = generate_data(account_email, account_name, managed_ou)

    return result

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(prog='enroll_account.py', usage='%(prog)s -o -u|-e|-i [-c]', \
                                    description='Enroll existing accounts to AWS Control Tower.')

    PARSER.add_argument("-o", "--ou", type=str, required=True, help="Target Registered OU")
    PARSER.add_argument("-u", "--unou", type=str, help="Origin UnRegistered OU")
    PARSER.add_argument("-e", "--email", type=str, \
                        help="AWS account email-address to enroll in to AWS Control Tower")
    PARSER.add_argument("-i", "--aid", type=str, \
                        help="AWS Account Id to enroll in to AWS Control Tower")
    PARSER.add_argument("-c", "--create_role", action='store_true', \
                        help="Create Roles on Root Level")

    SESSION = boto3.session.Session()
    STS = SESSION.client('sts')
    SC = SESSION.client('servicecatalog')
    ORG = SESSION.client('organizations')
    CFT = SESSION.client('cloudformation')
    REGION_NAME = SESSION.region_name

    ARGS = PARSER.parse_args()
    MANAGED_OU = ARGS.ou
    ROOT_LEVEL = ARGS.create_role

    if ARGS.unou:
        UNMANAGED_OU = ARGS.unou
        DATA = get_accounts_in_ou(UNMANAGED_OU, MANAGED_OU)
    elif ARGS.email:
        DATA = get_account_info(MANAGED_OU, account_email=ARGS.email)
    elif ARGS.aid:
        DATA = get_account_info(MANAGED_OU, account_id=ARGS.aid)
    else:
        error_and_exit('Need to pass atleast one option from [-u|-e|-i]')


    MASTER_ACCOUNT_ID = STS.get_caller_identity()['Account']

    EMAIL_ID = STS.get_caller_identity()['UserId'].split(':')[-1]

    LOGGER.info('Executing on AWS Account: %s, %s', MASTER_ACCOUNT_ID, EMAIL_ID)

    # Get list of Service Catalog provisioned products in AVAILABLE / ERROR state
    (ACCT_MAP, ERROR_LIST, TRANSIT_LIST) = get_provisioned_product_list()

    # Get the Product Id of the AWS Control Tower Account Factory
    PROD_ID = get_product_id()

    # Get the Provisioning Artifact Id of the AWS Control Tower Account Factory
    PA_ID = get_provisioning_artifact_id(PROD_ID)

    # for all items in the dataset migrate accounts sequentially
    if len(TRANSIT_LIST) > 0:
        MSG = 'Update in progress. Allow UNDER_CHANGE or PLAN_IN_PROGRESS stacks to complete: '
        error_and_exit(MSG + str(TRANSIT_LIST))
    else:
        for ACCOUNT_ID in DATA:
            account_data = DATA[ACCOUNT_ID]
            pp_status = 'UNDER_CHANGE'
            sleep_time = 360

            # Check if the AWS Control Tower role exists.
            role_exists = does_ct_role_exists(ACCOUNT_ID)
            retry = 0

            while not role_exists:
                create_crossaccount_role(ACCOUNT_ID, REGION_NAME, MASTER_ACCOUNT_ID)
                role_exists = does_ct_role_exists(ACCOUNT_ID)
                retry += 1
                if retry == 5:
                    error_and_exit('Failed to create ControlTowerExecution role - {}'.format(retry))

            if role_exists:

                PP_NAME = generate_provisioned_product_name(account_data)

                p_status = provision_sc_product(PROD_ID, PA_ID, PP_NAME, account_data)

                if not p_status:
                    pp_status = 'ERROR'

                # Wait until the Service Catalog Product Provisioning Completes
                while pp_status == 'UNDER_CHANGE':
                    print('Status: {}. Waiting for {} min to check back the Status'.\
                            format(pp_status, sleep_time/60))
                    sleep(sleep_time)
                    if sleep_time > 60:
                        sleep_time -= 60

                    pp_status = get_provisioned_product_status(PP_NAME)

                if pp_status == 'AVAILABLE':
                    LOGGER.info('SUCCESS: %s updated', ACCOUNT_ID)
                else:
                    LOGGER.error('%s: %s', pp_status, ACCOUNT_ID)
            else:
                LOGGER.error('Unable to create role for %s', ACCOUNT_ID)
