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
import boto3

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

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
    except Exception as e:
        error_and_exit('Unable to find Product Id: ' + str(e))

    for item in search_list:
        if key in item:
            if item[key]['Name'] == af_product_name:
                output = item[key]['ProductId']
                break
        else:
            LOGGER.warning('Unexepected output recieved. Skipping: {}'.format(item))

    if not output:
        error_and_exit('Unable to find Product Id: ' + str(search_list))

    return output

def get_provisioning_artifact_id(prod_id):
    ''' Query for Provisioned Artifact Id '''

    pa_list = list()

    try:
        pa_list = SC.describe_product(Id=prod_id)['ProvisioningArtifacts']
    except Exception as e:
        error_and_exit("Unable to find the Provisioned Artifact Id: " + str(e))

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
            acct_number = get_account_mapping(email_id)
            (acct_map, error_list, transit_list) = get_provisioned_product_list()
            pp_id = acct_map[acct_number]

    return pp_id

def get_provisioned_product_status(pp_id):
    ''' Query and return the Provisioned Product Current Status '''

    output = None
    pp_list = search_provisioned_product_full_list()

    for item in pp_list:
        if item['Id'] == pp_id:
            output = item['Status']
            break

    if not output:
        error_and_exit('Unable to find any provisioned products: ' + str(pp_id))

    return output

def update_sc_provisioned_product(pp_id, pa_id, prod_id, input_params, lang='en'):
    '''Update a previously provisioned Service Catalog Product '''

    try:
        result = SC.update_provisioned_product(AcceptLanguage=lang, ProductId=prod_id, \
                            ProvisioningArtifactId=pa_id, ProvisionedProductId=pp_id, \
                            ProvisioningParameters=input_params, \
                            UpdateToken=str(randint(1000000000000, 9999999999999)))
    except Exception as e:
        error_and_continue('SC product update failed: ' + str(e))

    return result

def list_org_roots():
    '''List organization roots'''

    value = None
    try:
        root_info = ORG.list_roots()
    except Exception as e:
        error_and_exit('Script should run on Organization root only: ' + str(e))

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
    except Exception as e:
        error_and_exit('Unable to get children list' + str(e))

    while 'NextToken' in child_dict:
        next_token = child_dict['NextToken']
        try:
            child_dict = ORG.list_children(ParentId=root_id, \
                        ChildType='ORGANIZATIONAL_UNIT', NextToken=next_token)
            child_list += child_dict['Children']
        except Exception as e:
            error_and_exit('Unable to get complete children list' + str(e))

    for item in child_list:
        org_info.append(item['Id'])

    if len(org_info) == 0:
        error_and_exit('No Organizational Units Found')

    return org_info

def get_ou_name(acct_id):
    '''Retrieve the OU name'''

    ou_list = list_all_ou()
    ou_map = {}
    output = None

    for ou in ou_list:
        try:
            ou_info = ORG.describe_organizational_unit(OrganizationalUnitId=ou)
            ou_name = ou_info['OrganizationalUnit']['Name']
        except Exception as e:
            error_and_exit('Unable to get the OU information' + str(e))

        try:
            acct_list = ORG.list_accounts_for_parent(ParentId=ou)['Accounts']
        except Exception as e:
            error_and_exit('Unable to get list of accounts' + str(e))

        for acct in acct_list:
            ou_map[acct['Id']] = ou_name

    if acct_id in ou_map:
        output = ou_map[acct_id]
    else:
        error_and_continue('Unable to find OU name for ' + str(acct_id))

    return output

def get_account_mapping(email_id):
    '''List of Accounts in an OU'''

    output = None

    try:
        acct_list = list_all_accounts()
    except Exception as e:
        error_and_exit('Failed to get list of accounts' + str(e))

    for acct in acct_list:
        if acct['Email'] == email_id:
            output = acct['Id']
            break

    if not output:
        error_and_exit('Unable to find an organization account')

    return output

def search_provisioned_product_full_list():
    '''Get complete list of provisioned products'''

    pp_list = list()
    filters = {"Key" : "Account", "Value" : "self"}

    try:
        pp_dict = SC.search_provisioned_products(AccessLevelFilter=filters)
        pp_list = pp_dict['ProvisionedProducts']
    except Exception as e:
        error_and_exit('Failed to get provisioned products list. ' + str(e))

    while 'NextPageToken' in pp_dict:
        next_token = pp_dict['NextPageToken']
        try:
            pp_dict = SC.search_provisioned_products(AccessLevelFilter=filters, PageToken=next_token)
            pp_list += pp_dict['ProvisionedProducts']
        except Exception as e:
            error_and_exit('Failed to get complete provisioned products list: ' + str(e))

    return(pp_list)

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

def get_acct_name(pp_id):
    '''Get account information for a given provisioned product id'''

    acct_name = None
    acct_id = None
    email_id = None
    ou_name = None

    (search_pp, error_pp, transit_pp) = search_provisioned_products()

    for item in search_pp:
        if item['Id'] == pp_id:
            acct_id = item['PhysicalId']
            break

    if acct_id and acct_id not in blacklist:
        for item in list_all_accounts():
            if item['Id'] == acct_id:
                email_id = item['Email']
                acct_name = item['Name']
                break

    if acct_id and acct_id not in blacklist:
        ou_name = get_ou_name(acct_id)

    return(acct_name, email_id, ou_name)

def tag_org_account(acct_no):
    '''Tag an account with in the organization'''

    output = None
    result = dict()
    tags = [{"Key": "PP_UPDATE", "Value": "TRUE"}]

    try:
        result = ORG.tag_resource(ResourceId=acct_no, Tags=tags)
        print('Tagged resource {}'.format(acct_no))
    except Exception as e:
        error_and_continue('Unable to Tag the resource: {}'.format(str(e)))

    if result:
        output = result['ResponseMetadata']['HTTPStatusCode']

    return output

def list_tags(acct_no):
    '''List tags for an AWS Account in the organization'''

    tag_dict = dict()
    output = list()

    try:
        tag_dict = ORG.list_tags_for_resource(ResourceId=acct_no)
    except Exception as e:
        error_and_continue('Unable to list tags for {}:{}'.format(acct_no, str(e)))

    if 'Tags' in tag_dict:
        output = tag_dict['Tags']

    return output

def is_resource_tagged(acct_no, tag_name='PP_UPDATE'):
    '''Return True if the resource is Tagged'''

    output = False
    tag_list = list_tags(acct_no)

    for item in tag_list:
        if item['Key'] == tag_name:
            output = True

    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='update_pp.py', usage='%(prog)s [-eflb]', description= \
                                    'Update all provisioned Account Factory products sequentially.')
    parser.add_argument("-e", "--email", type=str, default="noreply@example.com", \
                        help="SSOUserEmail")
    parser.add_argument("-f", "--fname", type=str, default="DoNot", \
                        help="SSOUserFirstName")
    parser.add_argument("-l", "--lname", type=str, default="Reply", \
                        help="SSOUserLastName")
    parser.add_argument("-b", "--blist", nargs='+', default="347805172924", \
                        help="List of accounts to blacklist")

    args = parser.parse_args()
    SSOUserEmail = args.email
    SSOUserFirstName = args.fname
    SSOUserLastName = args.lname
    blacklist = args.blist

    SC = boto3.client('servicecatalog')
    ORG = boto3.client('organizations')

    # Get list of Service Catalog provisioned products in AVAILABLE / ERROR state
    (acct_map, error_list, transit_list) = get_provisioned_product_list()

    # Skip stacks that are in ERROR state.
    if len(error_list) > 0:
        LOGGER.warning('\nProvisioned Products in ERROR state - SKIPPING: \n {}\n\n'.\
                        format(error_list))

    # Get the Product Id of the AWS Control Tower Account Factory
    prod_id = get_product_id()

    # Get the Provisioning Artifact Id of the AWS Control Tower Account Factory
    pa_id = get_provisioning_artifact_id(prod_id)

    if len(acct_map) == 0:
        print('{} Provisioned Products found to update. No action taken'.format(len(acct_map)))

    # Loop through all the provisioned accounts
    if len(transit_list) > 0:
        MSG = 'Update in progress. Allow UNDER_CHANGE or PLAN_IN_PROGRESS stacks to complete: '
        error_and_exit(MSG + str(transit_list))
    else:
        for acct_no in acct_map:
            pp_status = 'UNDER_CHANGE'
            if not is_resource_tagged(acct_no) and acct_no not in blacklist:
                sleep_time = 360
                print('Updating Provisioned Account : {}'.format(acct_no))

                pp_id = acct_map[acct_no]

                (AccountName, AccountEmail, ManagedOrganizationalUnit) = get_acct_name(pp_id)

                if not AccountName or not AccountEmail or not ManagedOrganizationalUnit:
                    LOGGER.error('Missing key information : {},{},{}'.\
                                format(AccountName, AccountEmail, ManagedOrganizationalUnit))
                    data = []
                else:
                    data = [
                        {'Value': SSOUserEmail, 'Key': 'SSOUserEmail'},
                        {'Value': SSOUserFirstName, 'Key': 'SSOUserFirstName'},
                        {'Value': SSOUserLastName, 'Key': 'SSOUserLastName'},
                        {'Value': ManagedOrganizationalUnit, 'Key': 'ManagedOrganizationalUnit'},
                        {'Value': AccountName, 'Key': 'AccountName'},
                        {'Value': AccountEmail, 'Key': 'AccountEmail'}
                    ]

                if len(data) > 0:
                    pp_id = get_provisioned_product_id(data)
                    update_sc_provisioned_product(pp_id, pa_id, prod_id, data)

                    # Wait until the Service Catalog Product Provisioning Completes
                    while pp_status == 'UNDER_CHANGE':
                        print('Status: {}. Waiting for {} min to check back the Status'.\
                                format(pp_status, sleep_time/60))
                        sleep(sleep_time)
                        if sleep_time > 60:
                            sleep_time -= 60

                        pp_status = get_provisioned_product_status(pp_id)

                    if pp_status == 'AVAILABLE':
                        print('SUCCESS: {} updated'.format(acct_no))
                        tag_org_account(acct_no)
                else:
                    LOGGER.warning('No valid information found for {}'.format(acct_no))

            elif acct_no in blacklist:
                LOGGER.warning('Account {} skipped, in blacklist'.format(acct_no))
            else:
                LOGGER.warning('Account {} Skipped, Updated already'.format(acct_no))
