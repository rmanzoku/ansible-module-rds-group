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


def sg(module, conn, params):

    try:
        result = conn.describe_db_security_groups(DBSecurityGroupName=params.get("name"))

        if params.get("state") == "present":
            if len(result['DBSecurityGroups'][0]['IPRanges']) == 0:
                present_ipranges = [i['CIDRIP'] for i in result['DBSecurityGroups'][0]['IPRanges']
                                    if i['Status'] == "authorized"]
            else:
                present_ipranges = []

            desire_ipranges = params.get('ip_ranges')
            authorize_ipranges = list(set(desire_ipranges) - set(present_ipranges))
            revoke_ipranges = list(set(present_ipranges) - set(desire_ipranges))

            # No diffence
            if (len(authorize_ipranges) == 0) and (len(revoke_ipranges) == 0):
                return False

            # Adjust diffence
            if len(authorize_ipranges) != 0:
                for i in authorize_ipranges:
                    conn.authorize_db_security_group_ingress(
                        DBSecurityGroupName=params.get("name"),
                        CIDRIP=i
                    )

            if len(revoke_ipranges) != 0:
                for i in revoke_ipranges:
                    conn.revoke_db_security_group_ingress(
                        DBSecurityGroupName=params.get("name"),
                        CIDRIP=i
                    )

            return True

        else:
            conn.delete_db_security_group(DBSecurityGroupName=params.get("name"))
            return True

    except ClientError as ex:
        if ex.response['Error']['Code'] != "DBSecurityGroupNotFound":
            raise ex

        # ない
        if params.get("state") == "present":
            conn.create_db_security_group(DBSecurityGroupName=params.get("name"),
                                          DBSecurityGroupDescription=params.get("description"))

            for i in params.get('ip_ranges', []):
                conn.authorize_db_security_group_ingress(
                    DBSecurityGroupName=params.get("name"),
                    CIDRIP=i
                )

            return True
        else:
            # なにもしない
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
            # purge_rules=dict(default=True, required=False, type='bool'),
            # purge_rules_egress=dict(default=True, required=False, type='bool')
        )
    )

    module = AnsibleModule(argument_spec=argument_spec)

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
