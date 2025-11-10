"""
Course Roster Lambda Function
Retrieves course offerings for a specific term.
Endpoint: /roster_classes/{term}/{subject}
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
    Lambda handler for course roster endpoint.
    Endpoint: GET /roster_classes/{term}/{subject}

    Args:
        event: Lambda event object from API Gateway
        context: Lambda context object

    Returns:
        Course roster data or error response
    """
    try:
        logger.info(f"Course roster request: {event.get('pathParameters', {})}")

        # Since authentication is handled by CognitoAuthorizer,
        # we can access user info from requestContext.authorizer.claims
        request_context = event.get('requestContext', {})
        authorizer = request_context.get('authorizer', {})
        claims = authorizer.get('claims', {})
        username = claims.get('cognito:username', 'anonymous')

        # Get path parameters
        path_params = event.get('pathParameters', {}) or {}
        term = path_params.get('term', '')
        subject = path_params.get('subject', '')

        if not term:
            return validation.safe_json_response({'error': 'Missing term parameter'}, status_code=400)

        # Validate term for injection attacks (consistent with original)
        if injectable_check(term):
            return validation.safe_json_response({'error': 'Invalid term format'}, status_code=400)

        # Get bucket name from environment
        bucket_name = os.environ.get('STATIC_BUCKET', 'iris-api-static-data-bucket')

        # Get course data from S3
        s3_client = boto3.client('s3')
        try:
            classes = s3_client.get_object(Bucket=bucket_name, Key=term)
            classes_json = json.loads(classes['Body'].read())
            all_courses = classes_json.get('course_lookup', [])

            # Filter by subject if provided
            if subject:
                filtered_courses = [course for course in all_courses if course.get('subject') == subject]
                all_courses = filtered_courses

            response_data = {
                "data": all_courses,
                "contentType": "application/json",
                "term": term,
                "subject": subject or "all"
            }

            logger.info(f"Successfully retrieved course data for term: {term}, subject: {subject}, user: {username}")
            return validation.safe_json_response(response_data)

        except s3_client.exceptions.NoSuchKey:
            logger.warning(f"Course data not found for term: {term}")
            return validation.safe_json_response({'error': f'Course data not available for {term}'}, status_code=404)
        except Exception as e:
            logger.error(f"S3 retrieval error: {str(e)}")
            return validation.safe_json_response({'error': str(e)}, status_code=500)

    except Exception as e:
        logger.error(f"Unexpected error in course roster handler: {str(e)}")
        return validation.safe_json_response({'error': 'Internal server error'}, status_code=500)