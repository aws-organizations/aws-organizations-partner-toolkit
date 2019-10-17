#Copyright 2008-2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.

#Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
#http://aws.amazon.com/apache2.0/
#or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.


#!/usr/bin/env python

from __future__ import print_function
import boto3
import botocore
import time
import sys
import argparse
import json

'''
AWS Organizations Create Account and Provision Resources via CloudFormation

This module creates a new organization (if needed) using the Organizations API, 
then calls CloudFormation to deploy baseline resources within that account via a 
local tempalte file.

'''

__version__ = '0.1'
__author__ = '@author@'
__email__ = '@email@'


def get_org(feature_set):

    '''
        Get properties of existing AWS organization 
    '''
    client = boto3.client('organizations')

    org_status = 'NOT_FOUND'
    org_id = 'NONE'

    print("Checking organization status...")

    try:
        org_response = client.describe_organization()

        # get the org ID
        OrganizationId=org_response.get('Organization').get('Id')
        print("Org ID is:" + OrganizationId)
        if OrganizationId: 
            org_status = 'FOUND'
            org_id = OrganizationId
            print("Organization ID:" + org_id + " " + org_status)

    except botocore.exceptions.ClientError as e:
        print("Oganization not found")
        #print(e)
        # create the organization
        org_status, org_id = create_org(feature_set)


    return org_status, org_id


def create_org(feature_set):

    '''
        Create a new AWS organization 
    '''
    client = boto3.client('organizations')

    org_id = 'NONE'

    '''
    # check to see if org exists
    print("Checking organization status...")
    OrganizationId=client.describe_organization().get('Organization').get('Id')
    if OrganizationId: 
        org_status = 'FOUND'
        org_id = OrganizationId
    else:
        # create organization
    '''

    print("Organization does not exist...")
    print("Creating organization...")
    
    try:
        org_response = client.create_organization(FeatureSet=feature_set)
        # get the org ID
        OrganizationId=org_response.get('Organization').get('Id')
        print("Org ID is:" + OrganizationId)
        if OrganizationId: 
            org_status = 'CREATED'
            org_id = OrganizationId
            print("Organization ID:" + org_id + " " + org_status)         

        '''
        # get the root ID
        list_roots_response = client.list_roots()
        root_id = list_roots_response.get('Roots')[0].get('Id')
        print('Root ID is: ' + root_id)
        '''


    except botocore.exceptions.ClientError as e:
        print('Error: Organization could NOT be created...')
        print(e)

    '''
    while org_status == 'IN_PROGRESS':
        #print(org_response)
        OrganizationId=org_response.get('Organization').get('Id')
        print("Org ID is:" + OrganizationId)
        if OrganizationId: 
            org_status = 'SUCCEEDED'
        else:
            time.sleep(10)
            org_response = client.describe_organization()
            print("Create organization status: " + org_status)

 
    root_id = client.list_roots().get('Roots')[0].get('Id')
    #roots_list_response = client.list_roots().get('Roots')
    #print("List of Roots: ", roots_list_response)

    # Enable the SERVICE CONTROL policy type in the new org
    try:
        enable_policy_response = client.enable_policy_type(
            RootId=root_id,
            PolicyType='SERVICE_CONTROL_POLICY'
        )
        #print("Enable policy response", enable_policy_response)
        # delay needed here - give the process time to finish or the subsequent create-policy routine will conflict/fail
        print('enabling the policy...')
        time.sleep(10)  

    except botocore.exceptions.ClientError as e:
        print('SERVICE CONTROL policy type NOT enabled...')
        print(e)
    '''

    return org_status, org_id



def enable_SCP_policy_type():

    '''
        Enable the SCP policy type 
    '''

    client = boto3.client('organizations')

    scp_type_status = 'NOT_ENABLED'
    print("Checking the SCP policy type...")

    # check to see if SCP policy type is enabled
    list_roots_response = client.list_roots()
    root_id = list_roots_response.get('Roots')[0].get('Id')
    policy_types = list_roots_response.get('Roots')[0].get('PolicyTypes')
    for p_type in policy_types:
        if p_type.get('Type') == 'SERVICE_CONTROL_POLICY':
            scp_type_status = p_type.get('Status')

    # Enable the SERVICE CONTROL policy type in the new org
    if scp_type_status != "ENABLED":
        try:
            enable_policy_type_response = client.enable_policy_type(
                RootId=root_id,
                PolicyType='SERVICE_CONTROL_POLICY'
            )

            # delay needed here - give the process time to finish or the subsequent create-policy routine will conflict/fail
            print('please wait...enabling the policy...')
            time.sleep(10)  

            print("Enable policy response", enable_policy_type_response)

            # check status of SCP policy type 
            policy_types = enable_policy_type_response.get('Root').get('PolicyTypes')
            for p_type in policy_types:
                if p_type.get('Type') == 'SERVICE_CONTROL_POLICY':
                    scp_type_status = p_type.get('Status')
            
            print('scp_type status >>>>')
            print(scp_type_status)

        except botocore.exceptions.ClientError as e:
            print('ERROR! SERVICE CONTROL policy type NOT enabled...')
            print(e)

    return scp_type_status


def create_scp(policy_name,policy_description,policy_type,policy_statement):

    '''
        Create a new Service Control Policy and attach to the root of the organization
    '''

    client = boto3.client('organizations')

    # see if the SCP already exists
    print("Checking service control policy... " + policy_name)
    list_policies_response = client.list_policies(
        Filter='SERVICE_CONTROL_POLICY'
    )
    scp_id = "NONE"
    scp_arn = "NONE"

    policies = list_policies_response.get("Policies")
    for policy in policies:
        scp_name=policy.get('Name')
        if scp_name == policy_name:
            scp_id=policy.get('Id')
            scp_arn=policy.get('Arn')

    ## if SCP does not exist, then create it
    if scp_id == 'NONE':
        print("Creating policy... " + policy_name)
        try:
            # create the policy
            create_policy_response = client.create_policy(
                Content=json.dumps(policy_statement),
                Description=policy_description,
                Name=policy_name,
                Type='SERVICE_CONTROL_POLICY'
            )

            # get the details for the new policy
            scp_id = create_policy_response.get('Policy').get('PolicySummary').get('Id')
            scp_arn = create_policy_response.get('Policy').get('PolicySummary').get('Arn')

        except botocore.exceptions.ClientError as e:
            print('Warning: SCP NOT created...')
            print(e)

    # attach the policy to the root
    root_id = client.list_roots().get('Roots')[0].get('Id')
    try:
        attach_policy_response = client.attach_policy(
            PolicyId=scp_id,
            TargetId=root_id
        )
    except botocore.exceptions.ClientError as e:
        # exit if stack already exists
        e_msg=str(e)
        if e_msg=='An error occurred (DuplicatePolicyAttachmentException) when calling the AttachPolicy operation: A policy with the specified name and type already exists.':
            print('Policy already attached...')

    return scp_id, scp_arn


def get_template(template_file):

    '''
        Read a template file and return the contents
    '''

    print("Reading resources from " + template_file)
    f = open(template_file, "r")
    cf_template = f.read()
    return cf_template


def deploy_resources(template, stack_name, stack_region, org_admin_password, partner_admin_password, protected_scp_arn):

    '''
        Create a CloudFormation stack of resources within the master payer account
    '''

    datestamp = time.strftime("%d/%m/%Y")
    client = boto3.client('cloudformation',
                          region_name=stack_region)

    """
    # test to see if stack already exists
    response = client.describe_stacks(
            StackName=stack_name,
        )
    print("Stack exists?>>>>>>>",response)
    """

    print("Creating stack " + stack_name + " in " + stack_region)

    creating_stack = True
    while creating_stack is True:
        try:
            creating_stack = False
            create_stack_response = client.create_stack(
                StackName=stack_name,
                TemplateBody=template,
                Parameters=[
                    {
                        'ParameterKey' : 'OrgAdminPassword',
                        'ParameterValue' : org_admin_password
                    },
                    {
                        'ParameterKey' : 'PartnerAdminPassword',
                        'ParameterValue' : partner_admin_password
                    },
                    {
                        'ParameterKey' : 'ProtectedSCPArn',
                        'ParameterValue' : protected_scp_arn
                    }
                ],
                NotificationARNs=[],
                Capabilities=[
                    'CAPABILITY_NAMED_IAM',
                ],
                OnFailure='ROLLBACK',
                Tags=[
                    {
                        'Key': 'ManagedResource',
                        'Value': 'True'
                    },
                    {
                        'Key': 'DeployDate',
                        'Value': datestamp
                    }
                ]
            )
        except botocore.exceptions.ClientError as e:
            creating_stack = True
            # exit if stack already exists
            e_msg=str(e)
            if e_msg=='An error occurred (AlreadyExistsException) when calling the CreateStack operation: Stack [master-payer-resources] already exists':
                print("Stack already exists... stack not created...")
                print("================ COMPLETE ==================")
                print(".")
                sys.exit(1) 
            else:        
                print("Retrying...")
                time.sleep(10)

    stack_building = True
    print("Stack creation in process...")
    #print(create_stack_response)
    try_count=0
    while stack_building is True:
        try_count+=1
        event_list = client.describe_stack_events(StackName=stack_name).get("StackEvents")
        stack_event = event_list[0]

        if (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
           stack_event.get('ResourceStatus') == 'CREATE_COMPLETE'):
            stack_building = False
            print("Stack construction complete.")
        elif (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
              stack_event.get('ResourceStatus') == 'ROLLBACK_COMPLETE'):
            stack_building = False
            print("Stack construction failed.")
            sys.exit(1)
        else:
            #print(stack_event)
            print("Stack building . . .")
            time.sleep(10)

    stack = client.describe_stacks(StackName=stack_name)
    return stack


def main(arguments):

    # accept incoming command line parameters
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--org_admin_password', required=True)
    parser.add_argument('--partner_admin_password', required=True)

    parser.add_argument('--template_file',
                        default='create-all-resources.yaml')
    parser.add_argument('--stack_name',
                        default='master-payer-resources')
    parser.add_argument('--stack_region',
                        default='us-east-1')

    args = parser.parse_args(arguments)

    # define constants
    organization_unit_id = None
    feature_set = 'ALL'
    scp = None

  
    # check to see if the organization already exists
    print(".")
    print("=============  ORGANIZATION ===============")
    org_status, org_id = get_org(feature_set)
    print("================ COMPLETE ==================")
    print(".")


    print(".")
    print("================ SCPs  =====================")
    # if SCP policy type not yet enabled on the organization, then it must be done
    scp_type_status = enable_SCP_policy_type()


    # create service control policies
    policy_description='Deny All Billing Functions'
    policy_name='DenyAllBilling'
    POLICY_TYPE='SERVICE_CONTROL_POLICY'
    policy_statement = {
        "Version": "2012-10-17",
        "Statement": [
                        {
                            "Effect": "Deny",
                            "Action": [
                                "cur:*",
                                "ce:*",
                                "aws-portal:*"
                            ],
                            "Resource": [
                                "*"
                            ]
                        }
                    ]
        }
    scp_id, scp_arn = create_scp(policy_name,policy_description,POLICY_TYPE,policy_statement)
    print("SCP policy type status: " + scp_type_status)
    print("SCP ID:  " + scp_id + "  SCP ARN: " + scp_arn)
    print("================ COMPLETE ==================")
    print(".")


    print(".")
    # create the IAM groups, policies and admin users
    print("========== USERS AND IAM POLICIES ==========")
    print("Deploying resources from " + args.template_file + " as " + args.stack_name + " in " + args.stack_region)
    template = get_template(args.template_file)
    stack = deploy_resources(template, args.stack_name, args.stack_region, args.org_admin_password, args.partner_admin_password,scp_arn)
    #print(stack)
    print("================ COMPLETE ==================")
    print(".")


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
