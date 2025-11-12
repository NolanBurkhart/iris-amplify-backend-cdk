"""
Schedule Data Lambda Function
Retrieves schedule/timing data for a specific term.
Endpoint: GET /grail/{term}
Authentication: Required (via CognitoAuthorizer)
"""
import os
import sys
import json
import logging
import boto3
from typing import Dict, Any
from curses.ascii import isalnum

# Add shared utilities to path (for Lambda layer)
sys.path.append('/opt/python')

# Import from shared layer
import validation

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def injectable_check(a: str) -> bool:
    """
    Simple injection check - matches original logic.
    Returns True if unsafe characters found.
    """
    for x in a:
        if not isalnum(x):
            return True
    return False

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for schedule data endpoint.
    Endpoint: GET /grail/{term}

    Args:
        event: Lambda event object from API Gateway
        context: Lambda context object

    Returns:
        Schedule data or error response
    """
    try:
        logger.info(f"Schedule data request: {event.get('pathParameters', {})}")

        # Since authentication is handled by CognitoAuthorizer,
        # we can access user info from requestContext.authorizer.claims
        request_context = event.get('requestContext', {})
        authorizer = request_context.get('authorizer', {})
        claims = authorizer.get('claims', {})
        username = claims.get('cognito:username', 'anonymous')

        # Get term from path parameters
        path_params = event.get('pathParameters', {}) or {}
        term = path_params.get('term', '')

        if not term:
            return validation.safe_json_response({'error': 'Missing term parameter'}, status_code=400)

        # Validate term for injection attacks (consistent with original)
        if injectable_check(term):
            return validation.safe_json_response({'error': 'Invalid term format'}, status_code=400)

        # Get bucket name from environment
        bucket_name = os.environ.get('STATIC_BUCKET', 'iris-api-static-data-bucket')

        # Get schedule data from S3
        s3_client = boto3.client('s3')
        try:
            # Construct key in original format
            key = f"{term}ts.json"
            classes = s3_client.get_object(Bucket=bucket_name, Key=key)["Body"]
            classes = json.loads(classes.read())

            response_data = {
                "data": classes,
                "contentType": "application/json",
                "term": term
            }

            logger.info(f"Successfully retrieved schedule data for term: {       
            }, user: {username}")
            return validation.safe_json_response(response_data)

        except s3_client.exceptions.NoSuchKey:
            logger.warning(f"Schedule data not found for term: {term}")
            return validation.safe_json_response({'error': f'Schedule data not available for {term}'}, status_code=404)
        except Exception as e:
            logger.error(f"S3 retrieval error: {str(e)}")
            return validation.safe_json_response({'error': str(e)}, status_code=500)

    except Exception as e:
        logger.error(f"Unexpected error in schedule data handler: {str(e)}")
        return validation.safe_json_response({'error': 'Internal server error'}, status_code=500)