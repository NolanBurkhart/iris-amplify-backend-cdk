"""
Health check Lambda function.
Provides a simple ping/pong endpoint to verify API Gateway and Lambda connectivity.
"""
import json
import logging
from typing import Dict, Any

# Add shared layer to path
import sys
import os
sys.path.append('/opt/python')

import validation

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for health check endpoint.
    Endpoint: GET /pong
    Authentication: Required (via CognitoAuthorizer)

    Args:
        event: Lambda event object from API Gateway
        context: Lambda context object

    Returns:
        JSON response with pong message and timestamp
    """
    try:
        logger.info("Health check endpoint called")

        # Since authentication is handled by CognitoAuthorizer,
        # we can access user info from requestContext.authorizer.claims
        request_context = event.get('requestContext', {})
        authorizer = request_context.get('authorizer', {})
        claims = authorizer.get('claims', {})

        # Extract user information if available
        username = claims.get('cognito:username', 'anonymous')
        email = claims.get('email', 'unknown')

        response_data = {
            "message": "pong",
            "timestamp": context.aws_request_id,
            "user": {
                "username": username,
                "email": email
            },
            "status": "healthy"
        }

        logger.info(f"Health check successful for user: {username}")
        return validation.safe_json_response(response_data)

    except Exception as e:
        logger.error(f"Health check error: {str(e)}")
        return validation.safe_json_response(
            {"error": "Internal server error", "message": str(e)},
            status_code=500
        )