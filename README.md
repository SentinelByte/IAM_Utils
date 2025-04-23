# Identity & Access Management Utilities

This repo contains Python scripts and utilities to assist with common identity & access management (IAM) operations.

Mainly for AWS environments. 

Focus areas include Service Control Policy (SCP) validation, permission auditing, and lightweight automation.

## Features

- Validate AWS SCP JSON structure and syntax
- Analyze IAM policies for overly permissive statements
- Helper scripts for working with AWS Organizations and Identity Center
- Easily extensible for custom IAM workflows

## Usage

```bash
# Example: validate an SCP file
python validate_scp.py <path-to-scp.json>
