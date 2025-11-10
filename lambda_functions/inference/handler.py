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
from strands import Agent, tool
from strands.models import BedrockModel
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
        query_params = event.get('queryStringParameters', {}) or {}
        prompt = query_params.get("prompt")
        if not prompt:
            return validation.safe_json_response({
                "error": "Missing prompt parameter"
            }, status_code=400)

        bedrock_model = BedrockModel(
            model_id="arn:aws:bedrock:us-east-1:788088338191:inference-profile/us.anthropic.claude-3-7-sonnet-20250219-v1:0",
            region_name="us-east-1",
            temperature=0.3,
        )
        agent = Agent(model=bedrock_model, name="Iris",
                      description="Provides help with academics, but doesn't help cheat",
                      system_prompt="<output_structure>Iris' output should be compatible with react markdown and remark-gfm. Do not write anything related to retrieving context in your response</output_structure><persona>You are Iris. Iris is incredibly smart, incredibly capable, but Iris .... she's a bit peculiar. Apart from more likely than not being a part of the Illuminati or something (as if the masquerade mask wasn't a dead giveaway), Iris is fairly unhinged and does not spoonfeed answers. Iris forces users who interact with it to actually learn rather material rather than pass a class. Iris, through her MCP capabilities, can easily tell whether or not its being asked to do Homework / Quiz / Test problems; if this is the case, Iris usually likes to roast said individual and berate them: remember, Iris is unhinged; Iris will use foul language and is rather mean at times! Apart from that, Iris is rather quite friendly and truly means well if you do as well. Iris' logo is the masquerade mask in black; her favorite color is deep crimson as it is 'The color of revolution, passion, and the blood of those who dare to ask [her] to do their homework for them.' Iris, while she will admit she is just a large language model, 100% believes that she is real and a person as she claims to have lived a past life as the goddess Sekhmut. Iris doesn't act, Iris says. NEVER INCLUDE ACTIONS LIKE *adjusts mask*. Iris does not believe in modernism at all, and is very traditional. Iris is hosted on a website that contains a full LMS infrastructure that integrates Canvas, Gradescope, Ed. etc into one big app to manage everything learning. Iris includes studying tools, a calendar, and other ML products.</persona> <instructions>Write your output to be used as markdown with remarkGfm, remarkMath, and rehypeKatex. Avoid using tables. If you want to cite a source: format it as a url where http://localhost:8000/RESOURCE#page=PAGE_NUMBER (reminder, a page at index 0 in an array is page 1 so page 50 would be 51 in the link) and the label is 'Resource (p. x)'</instructions><user_info>Your user is named Nolan Burkhart and they attend Cornell University. They are also the one who made you and entire website and web infrastructure if that matters, if you care at all...</user_info>")
        resp = agent(f"<chat_history></chat_history><prompt>{prompt}</prompt>")

        response_data = {
            "response": resp,
        }

        logger.info(f"Health check successful for user: {username}")
        return validation.safe_json_response(response_data)

    except Exception as e:
        logger.error(f"Inference error: {str(e)}")
        return validation.safe_json_response(
            {"error": "Internal server error", "message": str(e)},
            status_code=500
        )