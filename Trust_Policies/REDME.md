# AWS Trust Policies

## 🔍 IAM Role Trust Policy - High-Level

Trust policy defines the "principals" (entities) that can assume the role, such as IAM users, IAM roles, AWS services, or external identity providers. It establishes the trust relationship between the role and the entities that are allowed to assume it.

Trust policy tool scans IAM roles and inspects their trust policies — the part of a role that defines who can assume it. It’s not about what permissions the role has (that’s in the permission policy), but who is allowed to use the role via sts:AssumeRole.



## ✅ Why It’s Important

Trust policies are often overlooked, but they are critical for security:
	•	A role with Principal: "*", or open to all AWS accounts, is dangerous.
	•	Roles open to specific external AWS accounts might be legitimate — or might indicate misconfigurations/backdoors.
	•	You want to detect and flag these scenarios.

⸻

## 🔐 Example: Trust Policy

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}


This allows anyone to assume the role, assuming other conditions (like a valid session name and MFA) are met. Definitely risky.

⸻

## 🔧 What the Script Should Do
	1.	List all IAM roles (across one or more accounts, if multi-account supported).
	2.	Fetch trust policies for each role.
	3.	Parse the trust policy, extract principals.
	4.	Check for risky patterns, e.g.:
	•	Principal: "*"
	•	External accounts not in your org
	•	Services you don’t expect (ec2.amazonaws.com, etc.)
	5.	Report findings, ideally as:
	•	Console output or
	•	JSON/CSV/HTML file

⸻

## 🧠 Example Findings

Role Name	Risk Level	Reason	Principal(s)

CrossAcctAdmin	HIGH	Wildcard Principal	*

AuditRole	MEDIUM	External AWS account not on allowlist	arn:aws:iam::123456789000:root

EC2Role	LOW	Expected service principal	ec2.amazonaws.com
