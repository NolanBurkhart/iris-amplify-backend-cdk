"""
Degree Programs Lambda Function
Lists all available degree programs.
Endpoint: GET /list-degrees
Authentication: Required (via CognitoAuthorizer)
"""
import os
import sys
import logging
import boto3
from typing import Dict, Any

# Add shared utilities to path (for Lambda layer)
sys.path.append('/opt/python')

# Import from shared layer
import validation

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def to_friendly_name(key: str) -> str:
    """
    Convert file key to friendly name - matches original logic.
    """
    return key.replace("_", " ").split(".")[0]

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for degree programs listing endpoint.
    Endpoint: GET /list-degrees

    Args:
        event: Lambda event object from API Gateway
        context: Lambda context object

    Returns:
        List of available degree programs or error response
    """
    try:
        logger.info("Degree programs listing requested")

        # Since authentication is handled by CognitoAuthorizer,
        # we can access user info from requestContext.authorizer.claims
        request_context = event.get('requestContext', {})
        authorizer = request_context.get('authorizer', {})
        claims = authorizer.get('claims', {})
        username = claims.get('cognito:username', 'anonymous')

        # Get bucket name from environment
        bucket_name = os.environ.get('STATIC_BUCKET', 'iris-api-static-data-bucket')

        # List degree programs from S3
        s3_client = boto3.client('s3')
        try:
            classes = s3_client.list_objects(Bucket=bucket_name, Prefix="program-requirements/")

            if 'Contents' not in classes:
                logger.warning("No degree programs found")
                return validation.safe_json_response({
                    "data": {},
                    "contentType": "application/json"
                })

            keys = [x["Key"].split("/")[1] for x in classes['Contents']]

            # Create friendly name mapping (consistent with original logic)
            programs = {to_friendly_name(x): x for x in keys}

            response_data = {
                "data": programs,
                "contentType": "application/json"
            }

            logger.info(f"Successfully retrieved {len(programs)} degree programs for user: {username}")
            return validation.safe_json_response(response_data)

        except Exception as e:
            logger.error(f"S3 listing error: {str(e)}")
            return validation.safe_json_response({'error': str(e)}, status_code=500)

    except Exception as e:
        logger.error(f"Unexpected error in degree programs handler: {str(e)}")
        return validation.safe_json_response({'error': 'Internal server error'}, status_code=500)