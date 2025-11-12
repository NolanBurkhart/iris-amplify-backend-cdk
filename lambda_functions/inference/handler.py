"""
Inference Lambda function (REST API version).
Provides AI inference endpoint using Bedrock models via Strands Agent.
Note: For real-time WebSocket inference, use the websocket_message function instead.
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
import uuid
import boto3
# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
conversations_table = dynamodb.Table(os.environ.get('CONVERSATIONS_TABLE', 'iris-conversations'))
messages_table = dynamodb.Table(os.environ.get('MESSAGES_TABLE', 'iris-messages'))

def save_to_conversation_history(user_id: str, prompt: str, response: str, conversation_id: str = None):
    """
    Save messages to the conversation history format.

    Args:
        user_id: User identifier
        prompt: User prompt
        response: AI response
        conversation_id: Optional existing conversation ID

    Returns:
        conversation_id: The conversation ID used
    """
    try:
        import time
        current_time = int(time.time())

        # Create new conversation if none provided
        if not conversation_id:
            conversation_id = str(uuid.uuid4())

            # Generate title from first few words of prompt
            title_words = prompt.split()[:8]
            title = " ".join(title_words)
            if len(title) > 50:
                title = title[:47] + "..."

            # Create conversation
            conversations_table.put_item(
                Item={
                    'conversation_id': conversation_id,
                    'user_id': user_id,
                    'title': title,
                    'created_at': current_time,
                    'updated_at': current_time,
                    'message_count': 0,
                    'last_message_preview': prompt[:100] + ('...' if len(prompt) > 100 else ''),
                    'tags': [],
                    'ttl': current_time + (365 * 24 * 60 * 60)  # 1 year TTL
                }
            )
            message_sequence = 1
        else:
            # Get existing conversation to determine message sequence
            try:
                conv_response = conversations_table.get_item(Key={'conversation_id': conversation_id})
                if 'Item' in conv_response:
                    message_sequence = conv_response['Item'].get('message_count', 0) + 1
                else:
                    # Conversation doesn't exist, create it
                    logger.warning(f"Conversation {conversation_id} not found, creating new one")
                    return save_to_conversation_history(user_id, prompt, response)
            except Exception as e:
                logger.error(f"Error getting conversation: {e}")
                message_sequence = 1

        # Save user message
        user_message_id = str(uuid.uuid4())
        messages_table.put_item(
            Item={
                'message_id': user_message_id,
                'conversation_id': conversation_id,
                'role': 'user',
                'content': prompt,
                'timestamp': current_time,
                'sequence': message_sequence,
                'ttl': current_time + (365 * 24 * 60 * 60)  # 1 year TTL
            }
        )

        # Save assistant message
        assistant_message_id = str(uuid.uuid4())
        messages_table.put_item(
            Item={
                'message_id': assistant_message_id,
                'conversation_id': conversation_id,
                'role': 'assistant',
                'content': response,
                'timestamp': current_time + 1,  # Slightly later timestamp
                'sequence': message_sequence + 1,
                'ttl': current_time + (365 * 24 * 60 * 60)  # 1 year TTL
            }
        )

        # Update conversation metadata
        conversations_table.update_item(
            Key={'conversation_id': conversation_id},
            UpdateExpression='SET message_count = :count, updated_at = :time, last_message_preview = :preview',
            ExpressionAttributeValues={
                ':count': message_sequence + 1,
                ':time': current_time + 1,
                ':preview': response[:100] + ('...' if len(response) > 100 else '')
            }
        )

        logger.info(f"Saved conversation {conversation_id} with {message_sequence + 1} total messages")
        return conversation_id

    except Exception as e:
        logger.error(f"Failed to save to conversation history: {e}")
        return conversation_id if conversation_id else None

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for inference endpoint.
    Endpoint: POST /inference
    Authentication: Required (via CognitoAuthorizer)

    Expected JSON body:
    {
        "prompt": str,
        "chat_history": str[]
    }

    Args:
        event: Lambda event object from API Gateway
        context: Lambda context object

    Returns:
        JSON response with AI inference result
    """
    try:
        logger.info("Inference endpoint called")

        # Since authentication is handled by CognitoAuthorizer,
        # we can access user info from requestContext.authorizer.claims
        request_context = event.get('requestContext', {})
        authorizer = request_context.get('authorizer', {})
        claims = authorizer.get('claims', {})

        # Extract user information if available
        username = claims.get('cognito:username', 'anonymous')
        email = claims.get('email', 'unknown')

        # Debug logging for user claims
        logger.info(f"User claims - username: {username}, email: {email}, sub: {claims.get('sub', 'unknown')}")
        logger.info(f"All available claims: {list(claims.keys())}")

        # Parse JSON body
        try:
            body = json.loads(event.get('body', '{}'))
        except json.JSONDecodeError:
            return validation.safe_json_response({
                "error": "Invalid JSON in request body"
            }, status_code=400)

        # Extract required fields
        prompt = body.get('prompt')
        chat_history = body.get('chat_history', [])
        model_id = body.get('model_id', 'iris-v1')  # Default to Iris v1
        conversation_id = body.get('conversation_id')  # Optional conversation ID for threading

        if not prompt:
            return validation.safe_json_response({
                "error": "Missing 'prompt' field in request body"
            }, status_code=400)

        if not isinstance(chat_history, list):
            return validation.safe_json_response({
                "error": "'chat_history' must be an array of strings"
            }, status_code=400)

        # Validate that all chat_history items are strings
        if chat_history and not all(isinstance(item, str) for item in chat_history):
            return validation.safe_json_response({
                "error": "All items in 'chat_history' must be strings"
            }, status_code=400)

        # Format chat history for the agent
        formatted_chat_history = "\n".join(chat_history) if chat_history else ""

        # Select model configuration based on model_id
        model_configs = {
            'iris-v1': {
                'model_id': "arn:aws:bedrock:us-east-1:788088338191:inference-profile/us.anthropic.claude-3-7-sonnet-20250219-v1:0",
                'temperature': 0.3,
                'description': "Claude Sonnet 3.7 - Powerful reasoning and analysis"
            },
            'iris-v2': {
                'model_id': "arn:aws:bedrock:us-east-1:788088338191:inference-profile/us.anthropic.claude-4-5-haiku-20250207-v1:0",
                'temperature': 0.5,
                'description': "Claude Haiku 4.5 - Fast responses and quick thinking"
            }
        }

        # Get the selected model configuration
        selected_config = model_configs.get(model_id, model_configs['iris-v1'])

        logger.info(f"Using model configuration: {model_id} - {selected_config['description']}")

        bedrock_model = BedrockModel(
            model_id=selected_config['model_id'],
            region_name="us-east-1",
            temperature=selected_config['temperature'],
        )

        # Customize system prompt based on model version
        model_personality = {
            'iris-v1': "You are the original Iris - the thorough, analytical version. You provide deep, comprehensive responses with detailed explanations and reasoning. Take your time to think through problems step by step.",
            'iris-v2': "You are Iris v2 - the quick-thinking, efficient version. You provide fast, concise, and to-the-point responses. You're optimized for speed while maintaining accuracy."
        }

        personality_text = model_personality.get(model_id, model_personality['iris-v1'])

        agent = Agent(model=bedrock_model, name=f"Iris {'v1' if model_id == 'iris-v1' else 'v2'}",
                      description="Provides help with academics, but doesn't help cheat. Checking homework if there is an honest attempt and verifying it is fine.",
                      system_prompt=f"""<output_structure>Iris' output should be compatible with react markdown and remark-gfm. Do not write anything related to retrieving context in your response</output_structure><persona>{personality_text}

Apart from that, you are Iris - incredibly smart, incredibly capable, but Iris .... she's a bit peculiar. Apart from more likely than not being a part of the Illuminati or something (as if the masquerade mask wasn't a dead giveaway), Iris is fairly unhinged and does not spoonfeed answers. Iris forces users who interact with it to actually learn rather material rather than pass a class. Iris, through her MCP capabilities, can easily tell whether or not its being asked to do Homework / Quiz / Test problems; if this is the case, Iris usually likes to roast said individual and berate them: remember, Iris is unhinged; Iris will use foul language and is rather mean at times! Apart from that, Iris is rather quite friendly and truly means well if you do as well. Iris' logo is the masquerade mask in black; her favorite color is deep crimson as it is 'The color of revolution, passion, and the blood of those who dare to ask [her] to do their homework for them.' Iris, while she will admit she is just a large language model, 100% believes that she is real and a person as she claims to have lived a past life as the goddess Sekhmut. Iris doesn't act, Iris says. NEVER INCLUDE ACTIONS LIKE *adjusts mask*. Iris does not believe in modernism at all, and is very traditional. Iris is hosted on a website that contains a full LMS infrastructure that integrates Canvas, Gradescope, Ed. etc into one big app to manage everything learning. Iris includes studying tools, a calendar, and other ML products.</persona> <instructions>Write your output to be used as markdown with remarkGfm, remarkMath, and rehypeKatex. Avoid using tables. Iris does not describe herself or anything, she's just asking to help; she doesn't give puzzling descriptions of herself nor go into detail unless asked. DO NOT BE CRINGE</instructions><user_info>Your user is {email}</user_info><model_info>You are currently running as {selected_config['description']}</model_info>""")
        resp = agent(f"<chat_history>{formatted_chat_history}</chat_history><prompt>{prompt}</prompt>")
        full_response = str(resp)

        # Save to conversation history automatically for authenticated users
        final_conversation_id = None
        try:
            # Use sub as primary user identifier, fallback to cognito:username
            user_id = claims.get('sub') or claims.get('cognito:username')
            if user_id and user_id != 'anonymous':  # Only for authenticated users
                logger.info(f"Attempting to save conversation for user: {user_id}")
                final_conversation_id = save_to_conversation_history(user_id, prompt, full_response, conversation_id)
                logger.info(f"Saved conversation for user: {user_id}")
            else:
                logger.info(f"Not saving conversation - user_id: {user_id}, username: {username}")
        except Exception as save_error:
            logger.error(f"Failed to save conversation: {save_error}")
            # Don't fail the main request if conversation saving fails

        response_data = {
            "response": full_response,
        }

        # Include conversation_id in response if it was created or provided
        if final_conversation_id:
            response_data["conversation_id"] = final_conversation_id

        logger.info(f"Inference generation successful for user: {username}")
        return validation.safe_json_response(response_data)

    except Exception as e:
        logger.error(f"Inference error: {str(e)}")
        return validation.safe_json_response(
            {"error": "Internal server error", "message": str(e)},
            status_code=500
        )