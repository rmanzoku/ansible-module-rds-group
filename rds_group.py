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
    from botocore.exceptions import ClientError
    HAS_BOTOCORE = True
except ImportError:
    HAS_BOTOCORE = False

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import ec2_argument_spec, boto3_conn, get_aws_connection_info


def sg(module, conn, params):

    try:
        result = conn.describe_db_security_groups(DBSecurityGroupName=params.get("name"))

        if params.get("state") == "present":
            for r in result['DBSecurityGroups'][0]['IPRanges']:
                print(r)
            # 差分チェック
            diff = False

            # 処理
            if diff is True:
                return True
            else:
                return False
        else:
            # conn.delete_db_security_group(DBSecurityGroupName=params.get("name"))
            return True

    except ClientError as ex:
        if ex.response['Error']['Code'] != "DBSecurityGroupNotFound":
            raise ex

        # ない
        if params.get("state") == "present":
            # conn.create_db_security_group(DBSecurityGroupName=params.get("name"),
            #                               DBSecurityGroupDescription=params.get("description"))
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
            ip_ranges=dict(type='list'),
            ec2_security_groups=dict(type='list'),
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

    except botocore.exceptions.NoCredentialsError as e:
        module.fail_json(msg=e.message)

    changed = sg(module, conn, module.params)
    module.exit_json(changed=changed)


if __name__ == '__main__':
    main()
