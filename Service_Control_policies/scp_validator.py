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
    """
    Return a basic JSON schema for validating AWS SCP structure.
    Reference - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html
    """
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



def validate_json_schema(json_data, schema):
    """Validate JSON data and report all schema issues."""
    try:
        validator = Draft7Validator(schema)
    except SchemaError as e:
        print("Schema error: The provided schema is invalid.")
        print(f"Details: {e}")
        sys.exit(1)

    errors = sorted(validator.iter_errors(json_data), key=lambda e: list(e.path))

    if not errors:
        print("Validation successful: JSON structure is valid.")
    else:
        print(f"Validation failed: {len(errors)} issue(s) found.")
        for i, error in enumerate(errors, start=1):
            location = ".".join([str(x) for x in error.absolute_path]) or "<root>"
            print(f"{i}. Location: {location}")
            print(f"   Error: {error.message}")
        sys.exit(1)



def main():
    if len(sys.argv) != 2:
        print("Usage: python validate_json.py <path_to_json_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    json_data = load_json_file(filepath)
    schema = get_scp_schema()
    validate_json_schema(json_data, schema)


if __name__ == "__main__":
    main()
