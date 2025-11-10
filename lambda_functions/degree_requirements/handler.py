"""
Degree Requirements Lambda Function
Retrieves detailed requirements for a specific degree program.
Endpoint: GET /degree-requirements.txt?degree={degree_name}
Authentication: Required (via CognitoAuthorizer)
"""
import os
import sys
import json
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

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for degree requirements endpoint.
    Endpoint: GET /degree-requirements.txt?degree={degree_name}

    Args:
        event: Lambda event object from API Gateway
        context: Lambda context object

    Returns:
        Degree requirements data or error response
    """
    try:
        logger.info(f"Degree requirements request: {event.get('queryStringParameters', {})}")

        # Since authentication is handled by CognitoAuthorizer,
        # we can access user info from requestContext.authorizer.claims
        request_context = event.get('requestContext', {})
        authorizer = request_context.get('authorizer', {})
        claims = authorizer.get('claims', {})
        username = claims.get('cognito:username', 'anonymous')

        # Get query parameters
        query_params = event.get('queryStringParameters', {}) or {}
        degree = query_params.get("degree")

        if not degree:
            return validation.safe_json_response({
                "error": "Missing degree parameter"
            }, status_code=400)

        # Basic input validation (consistent with original)
        if "/" in degree:
            return validation.safe_json_response({"error": "Invalid degree parameter"}, status_code=400)

        # Get bucket name from environment
        bucket_name = os.environ.get('STATIC_BUCKET', 'iris-api-static-data-bucket')

        try:
            # Construct S3 key (consistent with original logic)
            key = "program-requirements/" + degree.replace(" ", "_") + ".json"

            s3_client = boto3.client('s3')
            classes = s3_client.get_object(Bucket=bucket_name, Key=key)
            classes = json.loads(classes["Body"].read())

            response_data = {
                "data": classes,
                "contentType": "application/json",
                "degree": degree
            }

            logger.info(f"Successfully retrieved requirements for degree: {degree}, user: {username}")
            return validation.safe_json_response(response_data)

        except s3_client.exceptions.NoSuchKey:
            logger.warning(f"Degree requirements not found for: {degree}")
            return validation.safe_json_response({"Failure": f"Requirements not found for degree: {degree}"}, status_code=404)
        except Exception as e:
            logger.error(f"S3 retrieval error: {str(e)}")
            return validation.safe_json_response({"Failure": str(e)}, status_code=500)

    except Exception as e:
        logger.error(f"Unexpected error in degree requirements handler: {str(e)}")
        return validation.safe_json_response({'error': 'Internal server error'}, status_code=500)