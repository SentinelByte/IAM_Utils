import json
import sys
from jsonschema import Draft7Validator, SchemaError


def load_json_file(filepath):
    """Load a JSON file and return the parsed content."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON syntax in file: {filepath}")
        print(f"Details: {e}")
        sys.exit(1)



def get_scp_schema():
    """Return a basic JSON schema for validating AWS SCP structure."""
    return {
        "type": "object",
        "properties": {
            "Version": {
                "type": "string",
                "enum": ["2012-10-17"]
            },
            "Statement": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "Sid": {"type": "string"},
                        "Effect": {"type": "string", "enum": ["Deny", "Allow"]},
                        "Action": {
                            "oneOf": [
                                {"type": "string"},
                                {"type": "array", "items": {"type": "string"}}
                            ]
                        },
                        "Resource": {
                            "oneOf": [
                                {"type": "string"},
                                {"type": "array", "items": {"type": "string"}}
                            ]
                        },
                        "Condition": {"type": "object"}
                    },
                    "required": ["Effect", "Action", "Resource"],
                    "additionalProperties": False
                }
            }
        },
        "required": ["Version", "Statement"],
        "additionalProperties": False
    }

