# aws-control-tower-sso-management
Repository to manage AWS SSO with in AWS Control Tower

This is a solution to remove the AWS SSO entities and leave the service enabled with no active mappings. Mainly for those customer who do not want to use default AWS SSO deployed by AWS Control Tower. 
 
* Login to the Management Account and make sure you are in Control Tower Home Region.
* Launch stack, which creates:
* * A lambda function that:
* * 1. check/delete(s) the account mappings created by AWS Control Tower, and 
* * 2. Deleted the permission sets created by Control Tower.
* * An IAM role: that is assigned to above lambda with minimum required permissions.
* * An event rule:  that captured UpdateLandingZone and trigger ClearMappingsLambda function
 
