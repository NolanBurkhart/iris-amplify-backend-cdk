"""
Input validation and sanitization utilities for Iris Lambda functions.
Provides secure validation for user inputs to prevent injection attacks.
"""
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