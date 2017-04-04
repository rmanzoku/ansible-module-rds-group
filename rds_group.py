#!/usr/bin/python
# coding: utf-8

try:
    import boto
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False

try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

try:
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTOCORE = True
except ImportError:
    HAS_BOTOCORE = False

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import ec2_argument_spec, boto3_conn, get_aws_connection_info


def ec2groups_ingress(module, conn, name, present_ec2groups, desire_ec2groups):
    authorize_ec2groups = [i for i in desire_ec2groups if i not in present_ec2groups]
    revoke_ec2groups = [i for i in present_ec2groups if i not in desire_ec2groups]

    if (len(authorize_ec2groups) == 0) and (len(revoke_ec2groups) == 0):
        return False

    # Adjust diffence
    if len(authorize_ec2groups) != 0:
        for i in authorize_ec2groups:
            try:
                conn.authorize_db_security_group_ingress(
                    DBSecurityGroupName=name,
                    EC2SecurityGroupName=i['group_name'],
                    EC2SecurityGroupOwnerId=i['group_owner_id']
                )
            except ClientError as ex:
                module.fail_json(msg=ex.response['Error']['Message'])

    if len(revoke_ec2groups) != 0:
        for i in revoke_ec2groups:
            try:
                conn.revoke_db_security_group_ingress(
                    DBSecurityGroupName=name,
                    EC2SecurityGroupName=i['group_name'],
                    EC2SecurityGroupOwnerId=i['group_owner_id']
                )
            except ClientError as ex:
                module.fail_json(msg=ex.response['Error']['Message'])

    return True


def ipranges_ingress(conn, name, present_ipranges, desire_ipranges):
    return False
    authorize_ipranges = list(set(desire_ipranges) - set(present_ipranges))
    revoke_ipranges = list(set(present_ipranges) - set(desire_ipranges))

    # No diffence
    if (len(authorize_ipranges) == 0) and (len(revoke_ipranges) == 0):
        return False

    # Adjust diffence
    if len(authorize_ipranges) != 0:
        for i in authorize_ipranges:
            conn.authorize_db_security_group_ingress(
                DBSecurityGroupName=name,
                CIDRIP=i
            )

    if len(revoke_ipranges) != 0:
        for i in revoke_ipranges:
            conn.revoke_db_security_group_ingress(
                DBSecurityGroupName=name,
                CIDRIP=i
            )

    return True


def sg(module, conn, params):

    try:
        result = conn.describe_db_security_groups(DBSecurityGroupName=params.get("name"))

        if params.get("state") == "present":
            if len(result['DBSecurityGroups'][0]['IPRanges']) == 0:
                present_ipranges = []
            else:
                present_ipranges = [i['CIDRIP'] for i in result['DBSecurityGroups'][0]['IPRanges']
                                    if i['Status'] == "authorized"]

            ipranges_changed = ipranges_ingress(conn, params['name'],
                                                present_ipranges, params['ip_ranges'])

            if len(result['DBSecurityGroups'][0]['EC2SecurityGroups']) == 0:
                present_ec2groups = []

            else:
                present_ec2groups = [
                    {"group_owner_id": i['EC2SecurityGroupOwnerId'],
                     "group_name": i['EC2SecurityGroupName']}
                    for i in result['DBSecurityGroups'][0]['EC2SecurityGroups']
                    if i['Status'] == "authorized"]

            ec2groups_changed = ec2groups_ingress(module, conn, params['name'],
                                                  present_ec2groups, params['ec2_security_groups'])

            return ipranges_changed or ec2groups_changed

        else:
            # conn.delete_db_security_group(DBSecurityGroupName=params.get("name"))
            return True

    except ClientError as ex:
        if ex.response['Error']['Code'] != "DBSecurityGroupNotFound":
            raise ex

        # Create
        if params.get("state") == "present":
            conn.create_db_security_group(DBSecurityGroupName=params.get("name"),
                                          DBSecurityGroupDescription=params.get("description"))
            ipranges_ingress(conn,  params['name'], [], params['ip_ranges'])
            return True

        else:
            # Nothing to do
            return False


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type='str', required=True),
            description=dict(type='str', required=True),
            ip_ranges=dict(type='list', default=[]),
            ec2_security_groups=dict(type='list', default=[]),
            state=dict(default='present', type='str', choices=['present', 'absent']),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec)
    module.params['ec2_security_groups'] = [{'group_owner_id': str(i['group_owner_id']),
                                             'group_name': str(i['group_name'])}
                                            for i in module.params['ec2_security_groups']]
    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')
    if not HAS_BOTO:
        module.fail_json(msg='boto required for this module')

    try:
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
        conn = boto3_conn(module, conn_type="client", resource="rds", region=region,
                          **aws_connect_kwargs)

    except NoCredentialsError as e:
        module.fail_json(msg=e.message)

    changed = sg(module, conn, module.params)
    module.exit_json(changed=changed)


if __name__ == '__main__':
    main()
