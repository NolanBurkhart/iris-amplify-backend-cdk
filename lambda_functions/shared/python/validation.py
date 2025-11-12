"""
Input validation and sanitization utilities for Iris Lambda functions.
Provides secure validation for user inputs to prevent injection attacks.
"""
import json
import re
import logging
from typing import Optional, Dict, Any
from urllib.parse import unquote

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class ValidationError(Exception):
    """Custom exception for input validation errors."""
    pass

def validate_academic_term(term: str) -> bool:
    """
    Validate academic term format.

    Args:
        term: Academic term string (e.g., 'Fall2023', 'Spring2024A')

    Returns:
        True if valid, False otherwise
    """
    if not term or not isinstance(term, str):
        return False

    # Allow: Fall2023, Spring2024, Summer2023A, etc.
    # Pattern: (Fall|Spring|Summer|Winter) + 4-digit year + optional A/B
    pattern = r'^(Fall|Spring|Summer|Winter)\d{4}[AB]?$'

    if not re.match(pattern, term):
        return False

    # Additional length check
    if len(term) > 15:
        return False

    return True

def validate_subject_code(subject: str) -> bool:
    """
    Validate academic subject code.

    Args:
        subject: Subject code (e.g., 'CS', 'MATH', 'ENGL')

    Returns:
        True if valid, False otherwise
    """
    if not subject or not isinstance(subject, str):
        return False

    # Allow: 2-4 uppercase letters only
    pattern = r'^[A-Z]{2,4}$'

    return bool(re.match(pattern, subject))

def validate_degree_name(degree: str) -> bool:
    """
    Validate degree program name.

    Args:
        degree: Degree program name

    Returns:
        True if valid, False otherwise
    """
    if not degree or not isinstance(degree, str):
        return False

    # Allow: alphanumeric, spaces, dashes, parentheses, dots
    # Reject: path traversal, special characters
    pattern = r'^[a-zA-Z0-9\s\-\(\)\.]{1,100}$'

    if not re.match(pattern, degree):
        return False

    # Check for path traversal attempts
    if '..' in degree or '/' in degree or '\\' in degree:
        return False

    return True

def sanitize_degree_name(degree: str) -> str:
    """
    Sanitize degree name for safe S3 key construction.

    Args:
        degree: Raw degree name

    Returns:
        Sanitized degree name

    Raises:
        ValidationError: If degree name is invalid
    """
    if not validate_degree_name(degree):
        raise ValidationError(f"Invalid degree name: {degree}")

    # URL decode first (in case it's URL encoded)
    try:
        decoded = unquote(degree)
    except Exception:
        decoded = degree

    # Remove/replace problematic characters
    sanitized = re.sub(r'[^a-zA-Z0-9\s\-\(\)]', '', decoded)

    # Normalize spaces
    sanitized = ' '.join(sanitized.split())

    if not sanitized or len(sanitized.strip()) == 0:
        raise ValidationError("Degree name cannot be empty after sanitization")

    return sanitized.strip()

def validate_path_parameters(event: Dict[str, Any], required_params: list) -> Dict[str, str]:
    """
    Validate and extract path parameters from Lambda event.

    Args:
        event: Lambda event object
        required_params: List of required parameter names

    Returns:
        Dictionary of validated parameters

    Raises:
        ValidationError: If required parameters are missing or invalid
    """
    path_params = event.get('pathParameters') or {}

    validated_params = {}

    for param in required_params:
        value = path_params.get(param)

        if not value:
            raise ValidationError(f"Missing required parameter: {param}")

        # URL decode parameter
        try:
            decoded_value = unquote(value)
        except Exception:
            decoded_value = value

        # Validate based on parameter type
        if param in ['term']:
            if not validate_academic_term(decoded_value):
                raise ValidationError(f"Invalid term format: {decoded_value}")
        elif param in ['subject']:
            if not validate_subject_code(decoded_value):
                raise ValidationError(f"Invalid subject code: {decoded_value}")
        else:
            # Generic validation for other parameters
            if not isinstance(decoded_value, str) or len(decoded_value.strip()) == 0:
                raise ValidationError(f"Invalid parameter value: {param}")

        validated_params[param] = decoded_value

    return validated_params

def validate_query_parameters(event: Dict[str, Any], required_params: list = None, optional_params: list = None) -> Dict[str, str]:
    """
    Validate and extract query parameters from Lambda event.

    Args:
        event: Lambda event object
        required_params: List of required parameter names
        optional_params: List of optional parameter names

    Returns:
        Dictionary of validated parameters

    Raises:
        ValidationError: If required parameters are missing or invalid
    """
    query_params = event.get('queryStringParameters') or {}
    validated_params = {}

    # Validate required parameters
    if required_params:
        for param in required_params:
            value = query_params.get(param)

            if not value:
                raise ValidationError(f"Missing required query parameter: {param}")

            # URL decode parameter
            try:
                decoded_value = unquote(value)
            except Exception:
                decoded_value = value

            # Validate based on parameter type
            if param == 'degree':
                sanitized_value = sanitize_degree_name(decoded_value)
                validated_params[param] = sanitized_value
            else:
                validated_params[param] = decoded_value

    # Validate optional parameters
    if optional_params:
        for param in optional_params:
            value = query_params.get(param)

            if value:
                # URL decode parameter
                try:
                    decoded_value = unquote(value)
                except Exception:
                    decoded_value = value

                validated_params[param] = decoded_value

    return validated_params

def create_validation_error_response(error_message: str) -> Dict[str, Any]:
    """
    Create standardized validation error response.

    Args:
        error_message: Error message

    Returns:
        Formatted Lambda response
    """
    logger.warning(f"Validation error: {error_message}")

    return {
        'statusCode': 400,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'X-Iris-Token,Content-Type,Authorization',
            'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
        },
        'body': '{"error": "' + error_message.replace('"', '\\"') + '"}'
    }

def validate_required_fields(data: Dict[str, Any], required_fields: list) -> None:
    """
    Validate that all required fields are present in the data.

    Args:
        data: Dictionary to validate
        required_fields: List of required field names

    Raises:
        ValidationError: If any required field is missing
    """
    missing_fields = []
    for field in required_fields:
        if field not in data or data[field] is None:
            missing_fields.append(field)

    if missing_fields:
        raise ValidationError(f"Missing required fields: {', '.join(missing_fields)}")

def sanitize_input(input_str: str) -> str:
    """
    Sanitize user input by removing dangerous characters.

    Args:
        input_str: Raw input string

    Returns:
        Sanitized string
    """
    if not input_str:
        return ""

    # Convert to string if not already
    if not isinstance(input_str, str):
        input_str = str(input_str)

    # Remove null characters and control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f]', '', input_str)

    # Trim whitespace
    return sanitized.strip()

def validate_input_length(input_str: str, min_length: int, max_length: int, field_name: str = "input") -> str:
    """
    Validate input string length.

    Args:
        input_str: Input string to validate
        min_length: Minimum allowed length
        max_length: Maximum allowed length
        field_name: Name of the field for error messages

    Returns:
        Validated input string

    Raises:
        ValidationError: If length is invalid
    """
    if not input_str:
        if min_length > 0:
            raise ValidationError(f"{field_name} cannot be empty")
        return ""

    length = len(input_str)
    if length < min_length:
        raise ValidationError(f"{field_name} must be at least {min_length} characters long")

    if length > max_length:
        raise ValidationError(f"{field_name} cannot exceed {max_length} characters")

    return input_str

def create_error_response(status_code: int, error_code: str, message: str) -> Dict[str, Any]:
    """
    Create a standardized error response.

    Args:
        status_code: HTTP status code
        error_code: Application-specific error code
        message: Human-readable error message

    Returns:
        Formatted error response
    """
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
        },
        'body': json.dumps({
            'error': {
                'code': error_code,
                'message': message
            }
        })
    }

def create_success_response(data: Any, status_code: int = 200) -> Dict[str, Any]:
    """
    Create a standardized success response.

    Args:
        data: Response data
        status_code: HTTP status code

    Returns:
        Formatted success response
    """
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
        },
        'body': json.dumps(data, default=str)
    }

def safe_json_response(data: Any, status_code: int = 200) -> Dict[str, Any]:
    """
    Create safe JSON response with proper headers.

    Args:
        data: Data to serialize
        status_code: HTTP status code

    Returns:
        Formatted Lambda response
    """
    import json

    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'X-Iris-Token,Content-Type,Authorization',
            'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
        },
        'body': json.dumps(data)
    }