# SCP guardrail catalog

Each guardrail that `scp_builder.py` can emit: the spec key, the statements, what it protects, and the side effects to accept or work around before attaching it. Every guardrail is a Deny; none grants anything. SCPs do not affect the management account, service-linked roles, or principals outside the organization.

Protected roles (`protected_roles`) become an `ArnNotLike` condition on `aws:PrincipalArn` with `arn:aws:iam::*:role/<name>`. Keep the list short: every exempt role is a way around the guardrail.

## deny_leave_organization

- **Statement:** `DenyLeaveOrganization`: Deny `organizations:LeaveOrganization`.
- **Protects:** an attacker with admin in a member account cannot detach it from the organization, which would remove every other SCP and the organization trail.
- **Side effects:** none for normal operation. Moving an account out of the organization becomes a management-account task.

## deny_root_user

- **Statement:** `DenyRootUser`: Deny `*` when `aws:PrincipalArn` is like `arn:aws:iam::*:root`.
- **Protects:** member-account root users, which cannot be restricted by IAM, from doing anything.
- **Side effects:** the few tasks that require root (for example some account-level settings and closing the account through the console) need the SCP detached or the task done from the management account. With centralised root access management, member accounts can have no root credentials at all, which complements this guardrail.

## deny_disable_security_services

- **Statements:** `ProtectCloudTrail` (DeleteTrail, PutEventSelectors, StopLogging, UpdateTrail), `ProtectGuardDuty` (DeleteDetector, DeleteMembers, Disassociate*, StopMonitoringMembers, UpdateDetector), `ProtectSecurityHub` (BatchDisableStandards, DeleteMembers, DisableSecurityHub, Disassociate*), `ProtectConfig` (DeleteConfigurationRecorder, DeleteDeliveryChannel, DeleteRetentionConfiguration, StopConfigurationRecorder). Each carries the protected-role exemption.
- **Protects:** detection and audit logging from being switched off after a compromise.
- **Side effects:** `guardduty:UpdateDetector` and `cloudtrail:UpdateTrail` are also used for legitimate changes (finding frequency, protection plans, adding a bucket), so those changes must come from a protected role. Infrastructure as code that manages these resources needs its deployment role in `protected_roles`.

## allowed_regions

- **Statement:** `DenyOutsideAllowedRegions`: Deny with `NotAction` listing global and account-level services (IAM, STS, Organizations, Route 53, CloudFront, Support, billing and others), when `aws:RequestedRegion` is not in the list, with the protected-role exemption.
- **Protects:** against resources launched in regions nobody monitors, and narrows where stolen credentials can be used.
- **Side effects:** services whose control plane lives in `us-east-1` (some billing, Marketplace, global edge services) fail if `us-east-1` is not allowed and they are not in the NotAction list. AWS adds services, so compare the list with the current AWS documentation example. Regional STS endpoints in denied regions stop working, which is intended.

## deny_iam_users_outside

- **Statement:** `DenyIamUsersOutsideIdentityAccount`: Deny `iam:CreateUser`, `iam:CreateAccessKey`, `iam:CreateLoginProfile` unless `aws:PrincipalAccount` is one of the listed account ids.
- **Protects:** against long-lived IAM user credentials appearing in workload accounts; people and pipelines use IAM Identity Center and roles instead.
- **Side effects:** third-party tools that still require an IAM user and access key must be set up in the identity account, or the SCP detached for that account. Existing users and keys are not removed.

## require_imdsv2

- **Statements:** `RequireImdsv2OnLaunch` (Deny `ec2:RunInstances` on instances unless `ec2:MetadataHttpTokens` is `required`), `DenyImdsOptionChanges` (Deny `ec2:ModifyInstanceMetadataOptions` with the protected-role exemption), `DenyImdsv1RoleCredentials` (Deny `*` when `ec2:RoleDelivery` is below `2.0`).
- **Protects:** instance role credentials from server-side request forgery against the version 1 metadata service.
- **Side effects:** launch templates, Auto Scaling groups and older AMIs or SDKs that use IMDSv1 fail to launch or lose credentials. Set `HttpTokens=required` in launch templates first, and check the `MetadataNoToken` CloudWatch metric to find instances still using version 1.

## deny_public_s3_acls

- **Statements:** `DenyPublicS3CannedAcls` (Deny `s3:CreateBucket`, `s3:PutBucketAcl`, `s3:PutObject`, `s3:PutObjectAcl` when `s3:x-amz-acl` is `public-read`, `public-read-write` or `authenticated-read`), `ProtectAccountPublicAccessBlock` (Deny `s3:PutAccountPublicAccessBlock` with the protected-role exemption).
- **Protects:** against data made public through canned ACLs, and against the account-level public access block being turned off.
- **Side effects:** public static websites need a deliberate exception (an account in its own OU, or CloudFront with origin access control instead of public buckets). Bucket policies that grant public access are blocked by the public access block, not by this SCP.

## Size and attachment limits

- An SCP document can be at most 5120 characters. The builder measures the compact JSON form and packs statements in order into as few documents as fit.
- A root, OU or account can have at most 5 SCPs attached, including FullAWSAccess.
- Inheritance: an account is subject to every SCP attached to the root, to each OU above it and to itself.
