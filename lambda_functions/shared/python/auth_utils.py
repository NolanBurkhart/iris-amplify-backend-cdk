"""
Authentication utilities for Iris Lambda functions.
Provides enhanced Cognito token validation with proper JWT verification.
"""
import boto3
import json
import logging
import time
import os
import jwt
import requests
from typing import Optional, Dict, Any
from functools import lru_cache

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

@lru_cache(maxsize=1)
def get_jwks():
    """
    Fetch and cache JWT signing keys from Cognito.
    """
    user_pool_id = os.environ.get('USER_POOL_ID')
    aws_region = os.environ.get('AWS_REGION', 'us-east-1')

    if not user_pool_id:
        logger.error("USER_POOL_ID environment variable not set")
        return None

    jwks_url = f"https://cognito-idp.{aws_region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"

    try:
        response = requests.get(jwks_url, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Failed to fetch JWKS: {str(e)}")
        return None

def extract_auth_token(event: Dict[str, Any]) -> Optional[str]:
    """
    Extract authentication token from Lambda event.
    Supports both Authorization header and X-Iris-Token for backward compatibility.

    Args:
        event: Lambda event object

    Returns:
        Token string if found, None otherwise
    """
    headers = event.get('headers', {})

    # Try X-Iris-Token header first (custom header)
    auth_token = headers.get('X-Iris-Token')
    if auth_token:
        return auth_token

    # Try Authorization header (standard)
    auth_header = headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]  # Remove 'Bearer ' prefix

    # For API Gateway with Cognito authorizer, the token might be in requestContext
    request_context = event.get('requestContext', {})
    authorizer = request_context.get('authorizer', {})
    if authorizer and 'claims' in authorizer:
        # Token was already validated by API Gateway
        return authorizer.get('access_token') or 'api_gateway_validated'

    return None

def validate_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Validate JWT token using Cognito's public keys (preferred method).

    Args:
        token: JWT access token

    Returns:
        Token claims dict if valid, None otherwise
    """
    if not token or token == 'api_gateway_validated':
        return {'validated_by': 'api_gateway'} if token == 'api_gateway_validated' else None

    try:
        # Get JWKS (JSON Web Key Set)
        jwks = get_jwks()
        if not jwks:
            logger.error("Failed to get JWKS")
            return None

        # Decode JWT header to get key ID
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')

        if not kid:
            logger.error("Token missing key ID")
            return None

        # Find the correct key
        key = None
        for jwk in jwks.get('keys', []):
            if jwk.get('kid') == kid:
                key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
                break

        if not key:
            logger.error(f"Key not found for kid: {kid}")
            return None

        # Verify and decode token
        user_pool_id = os.environ.get('USER_POOL_ID')
        client_id = os.environ.get('USER_POOL_CLIENT_ID')
        aws_region = os.environ.get('AWS_REGION', 'us-east-1')

        issuer = f"https://cognito-idp.{aws_region}.amazonaws.com/{user_pool_id}"

        claims = jwt.decode(
            token,
            key,
            algorithms=['RS256'],
            issuer=issuer,
            audience=client_id,
            options={
                'verify_exp': True,
                'verify_aud': True,
                'verify_iss': True
            }
        )

        logger.info(f"Successfully validated JWT token for user: {claims.get('username', 'unknown')}")
        return claims

    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"JWT validation error: {str(e)}")
        return None

def validate_cognito_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Validate Cognito access token and return user information.
    Uses JWT validation as primary method, falls back to Cognito API if needed.

    Args:
        token: Cognito access token

    Returns:
        User information dict if valid, None otherwise
    """
    if not token:
        logger.warning("No token provided for validation")
        return None

    # Try JWT validation first (faster and doesn't count against API limits)
    jwt_claims = validate_jwt_token(token)
    if jwt_claims:
        if jwt_claims.get('validated_by') == 'api_gateway':
            return {'username': 'api_gateway_user', 'email': 'validated@api.gateway'}

        # Extract user info from JWT claims
        user_info = {
            'username': jwt_claims.get('username'),
            'email': jwt_claims.get('email'),
            'token_use': jwt_claims.get('token_use'),
            'client_id': jwt_claims.get('client_id'),
            'exp': jwt_claims.get('exp'),
            'iat': jwt_claims.get('iat')
        }
        return user_info

    # Fallback to Cognito API validation if JWT validation fails
    logger.info("JWT validation failed, falling back to Cognito API")
    try:
        # Initialize Cognito client
        cognito_client = boto3.client('cognito-idp', region_name=os.environ.get('AWS_REGION', 'us-east-1'))

        # Validate token with Cognito
        response = cognito_client.get_user(AccessToken=token)

        # Extract user information
        user_info = {
            'username': response.get('Username'),
            'attributes': {},
            'user_status': response.get('UserStatus')
        }

        # Parse user attributes
        for attr in response.get('UserAttributes', []):
            user_info['attributes'][attr['Name']] = attr['Value']

        # Get email from attributes
        user_info['email'] = user_info['attributes'].get('email', '')

        logger.info(f"Successfully validated token via API for user: {user_info.get('email', 'unknown')}")
        return user_info

    except cognito_client.exceptions.NotAuthorizedException:
        logger.warning("Token validation failed: Not authorized")
        return None
    except cognito_client.exceptions.UserNotConfirmedException:
        logger.warning("Token validation failed: User not confirmed")
        return None
    except Exception as e:
        logger.error(f"Token validation error: {str(e)}")
        return None

def create_auth_response(status_code: int, message: str) -> Dict[str, Any]:
    """
    Create standardized authentication response.

    Args:
        status_code: HTTP status code
        message: Error message

    Returns:
        Formatted Lambda response
    """
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'X-Iris-Token,Content-Type,Authorization',
            'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
        },
        'body': json.dumps({
            'error': message,
            'timestamp': str(int(time.time()))  # Unix timestamp
        })
    }

def require_authentication(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Decorator-style function to require authentication for Lambda functions.

    Args:
        event: Lambda event object

    Returns:
        User info if authenticated, error response if not
    """
    # Extract token
    token = extract_auth_token(event)
    if not token:
        return create_auth_response(401, "Authentication token required")

    # Validate token
    user_info = validate_cognito_token(token)
    if not user_info:
        return create_auth_response(401, "Invalid or expired authentication token")

    return user_info