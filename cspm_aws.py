import boto3

def check_public_s3_buckets():
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    public_buckets = []

    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                permission = grant.get('Permission', '')
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' and permission in ['READ', 'FULL_CONTROL', 'WRITE']:
                    public_buckets.append(bucket_name)
                    break
        except Exception as e:
            print(f"Could not get ACL for {bucket_name}: {e}")

    return public_buckets

def remediate_s3_bucket_public_access(bucket_name):
    s3 = boto3.client('s3')
    try:
        print(f"Removing public ACLs from bucket {bucket_name}...")
        s3.put_bucket_acl(Bucket=bucket_name, ACL='private')
        print(f"Bucket {bucket_name} ACL set to private.")
    except Exception as e:
        print(f"Failed to remediate bucket {bucket_name}: {e}")

def check_iam_roles():
    iam = boto3.client('iam')
    roles = iam.list_roles()['Roles']
    risky_roles = []

    for role in roles:
        role_name = role['RoleName']
        try:
            policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            for policy in policies:
                # Flag any role with AdministratorAccess attached
                if policy['PolicyName'] == 'AdministratorAccess':
                    risky_roles.append(role_name)
                    break
        except Exception as e:
            print(f"Error checking policies for {role_name}: {e}")

    return risky_roles

def remediate_iam_role(role_name):
    iam = boto3.client('iam')
    try:
        print(f"Detaching AdministratorAccess policy from role {role_name}...")
        iam.detach_role_policy(RoleName=role_name, PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        print(f"Policy detached from role {role_name}.")
    except Exception as e:
        print(f"Failed to remediate role {role_name}: {e}")

def check_security_groups():
    ec2 = boto3.client('ec2')
    security_groups = ec2.describe_security_groups()['SecurityGroups']
    risky_sgs = []

    for sg in security_groups:
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', 'N/A')
        for permission in sg['IpPermissions']:
            for ip_range in permission.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                if cidr == '0.0.0.0/0':
                    risky_sgs.append({'GroupId': sg_id, 'GroupName': sg_name})
                    break

    return risky_sgs

def remediate_security_group(sg_id):
    ec2 = boto3.client('ec2')
    try:
        # Revoke ingress for 0.0.0.0/0 on all ports
        sg = ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        permissions_to_revoke = []

        for permission in sg['IpPermissions']:
            ip_ranges = [ip for ip in permission.get('IpRanges', []) if ip.get('CidrIp') == '0.0.0.0/0']
            if ip_ranges:
                permissions_to_revoke.append({
                    'IpProtocol': permission['IpProtocol'],
                    'FromPort': permission.get('FromPort'),
                    'ToPort': permission.get('ToPort'),
                    'IpRanges': ip_ranges
                })

        if permissions_to_revoke:
            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=permissions_to_revoke)
            print(f"Revoked open ingress rules from security group {sg_id}.")
        else:
            print(f"No open ingress rules found in security group {sg_id} during remediation.")
    except Exception as e:
        print(f"Failed to remediate security group {sg_id}: {e}")

def generate_report(public_buckets, risky_roles, risky_sgs):
    print("\n--- AWS CSPM Report ---\n")
    
    if public_buckets:
        print("Publicly Accessible S3 Buckets:")
        for bucket in public_buckets:
            print(f" - {bucket}")
    else:
        print("No publicly accessible S3 buckets found.")
    
    print("\nIAM Roles with AdministratorAccess:")
    if risky_roles:
        for role in risky_roles:
            print(f" - {role}")
    else:
        print("No risky IAM roles found.")

    print("\nSecurity Groups with Open Inbound Rules (0.0.0.0/0):")
    if risky_sgs:
        for sg in risky_sgs:
            print(f" - {sg['GroupName']} ({sg['GroupId']})")
    else:
        print("No security groups with open inbound rules found.")

def prompt_remediation(public_buckets, risky_roles, risky_sgs):
    if public_buckets:
        print("\nRemediation: Public S3 Buckets")
        for bucket in public_buckets:
            answer = input(f"Do you want to remediate (set ACL to private) bucket '{bucket}'? (y/n): ")
            if answer.lower() == 'y':
                remediate_s3_bucket_public_access(bucket)

    if risky_roles:
        print("\nRemediation: IAM Roles")
        for role in risky_roles:
            answer = input(f"Do you want to detach AdministratorAccess policy from role '{role}'? (y/n): ")
            if answer.lower() == 'y':
                remediate_iam_role(role)

    if risky_sgs:
        print("\nRemediation: Security Groups")
        for sg in risky_sgs:
            answer = input(f"Do you want to revoke open inbound rules from security group '{sg['GroupName']}' ({sg['GroupId']})? (y/n): ")
            if answer.lower() == 'y':
                remediate_security_group(sg['GroupId'])

if __name__ == "__main__":
    print("Running AWS CSPM checks...")
    public_buckets = check_public_s3_buckets()
    risky_roles = check_iam_roles()
    risky_sgs = check_security_groups()

    generate_report(public_buckets, risky_roles, risky_sgs)

    prompt = input("\nDo you want to start remediation? (y/n): ")
    if prompt.lower() == 'y':
        prompt_remediation(public_buckets, risky_roles, risky_sgs)
    else:
        print("Remediation skipped.")
