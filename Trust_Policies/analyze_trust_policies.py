#!/usr/bin/env python3

import boto3
import json
from typing import List, Dict

iam_client = boto3.client('iam')


def list_roles() -> List[Dict]:
    """List all IAM roles in the account."""
    roles = []
    paginator = iam_client.get_paginator('list_roles')
    for page in paginator.paginate():
        roles.extend(page['Roles'])
    return roles


def analyze_trust_policy(policy_doc: Dict, role_name: str) -> List[Dict]:
    """Analyze trust policy document for risky principals."""
    findings = []
    statements = policy_doc.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        principal = stmt.get('Principal', {})
        effect = stmt.get('Effect', '')
        action = stmt.get('Action', '')

        if effect != "Allow" or "sts:AssumeRole" not in action:
            continue

        if isinstance(principal, str) and principal == "*":
            findings.append({
                'role': role_name,
                'risk': 'HIGH',
                'reason': 'Principal is wildcard "*"'
            })
            continue

        if isinstance(principal, dict):
            for principal_type, value in principal.items():
                if isinstance(value, str):
                    value = [value]

                for principal_entry in value:
                    if principal_entry == "*":
                        findings.append({
                            'role': role_name,
                            'risk': 'HIGH',
                            'reason': 'Principal is wildcard "*"'
                        })
                    elif principal_type == "AWS":
                        if not principal_entry.startswith("arn:aws:iam::"):
                            findings.append({
                                'role': role_name,
                                'risk': 'MEDIUM',
                                'reason': f'Unusual AWS principal format: {principal_entry}'
                            })
                        elif not principal_entry.endswith(":root"):
                            findings.append({
                                'role': role_name,
                                'risk': 'LOW',
                                'reason': f'Specific user or role in AWS principal: {principal_entry}'
                            })
                        else:
                            account_id = principal_entry.split("::")[1].split(":")[0]
                            if account_id != get_account_id():
                                findings.append({
                                    'role': role_name,
                                    'risk': 'MEDIUM',
                                    'reason': f'External AWS account: {account_id}'
                                })
                    elif principal_type in ["Service", "Federated"]:
                        findings.append({
                            'role': role_name,
                            'risk': 'LOW',
                            'reason': f'{principal_type} principal: {principal_entry}'
                        })
    return findings

