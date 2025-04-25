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
