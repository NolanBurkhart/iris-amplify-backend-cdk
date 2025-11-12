from constructs import Construct
import os
from aws_cdk import (
    Duration,
    Stack,
    RemovalPolicy,
    aws_iam as iam,
    aws_sqs as sqs,
    aws_sns as sns,
    aws_sns_subscriptions as subs,
    aws_cognito as cognito,
    aws_cognito_identitypool as cognito_identitypool,
    aws_apigateway as apigateway,
    aws_apigatewayv2 as apigatewayv2,
    aws_amplify as amplify,
    aws_lambda as lamb,
    aws_s3 as s3,
    aws_dynamodb as dynamodb,
    CfnOutput,
)


class IrisCdkAmplifyStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)



        queue = sqs.Queue(
            self, "IrisCdkAmplifyQueue",
            visibility_timeout=Duration.seconds(300),
        )

        topic = sns.Topic(
            self, "IrisCdkAmplifyTopic"
        )

        topic.add_subscription(subs.SqsSubscription(queue))

        # ===================================
        # API GATEWAY AND LAMBDA SETUP
        # ===================================

        # Use existing Cognito resources
        # Reference existing User Pool ID from your configuration
        existing_user_pool_id = "us-east-1_u4naAU0GM"
        existing_user_pool_client_id = "7ffio0fhu4h2fdo0p9jtdf1goo"
        existing_identity_pool_id = "us-east-1:78d1c556-231c-47b8-aa03-a45fc57360ee"

        # Import existing Cognito User Pool
        iris_cognito_user_pool = cognito.UserPool.from_user_pool_id(
            self, "ExistingUserPool",
            user_pool_id=existing_user_pool_id
        )

        # Create S3 buckets for data storage
        static_bucket = s3.Bucket(
            self, "IrisStaticBucket",
            bucket_name="iris-api-static-data-bucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True
        )

        user_bucket = s3.Bucket(
            self, "IrisUserBucket",
            bucket_name="iris-api-user-data-bucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True
        )

        # Create DynamoDB tables for WebSocket management
        connections_table = dynamodb.Table(
            self, "IrisWebSocketConnections",
            table_name="iris-websocket-connections",
            partition_key=dynamodb.Attribute(
                name="connection_id",
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl"
        )

        chat_sessions_table = dynamodb.Table(
            self, "IrisChatSessions",
            table_name="iris-chat-sessions",
            partition_key=dynamodb.Attribute(
                name="session_id",
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl"
        )

        # Add GSI for querying sessions by user
        chat_sessions_table.add_global_secondary_index(
            index_name="user-sessions-index",
            partition_key=dynamodb.Attribute(
                name="user_id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="created_at",
                type=dynamodb.AttributeType.STRING
            )
        )

        # Create DynamoDB tables for conversation history
        conversations_table = dynamodb.Table(
            self, "IrisConversations",
            table_name="iris-conversations",
            partition_key=dynamodb.Attribute(
                name="conversation_id",
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl"
        )

        # Add GSI for querying conversations by user with creation time sorting
        conversations_table.add_global_secondary_index(
            index_name="user_id-created_at-index",
            partition_key=dynamodb.Attribute(
                name="user_id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="created_at",
                type=dynamodb.AttributeType.NUMBER
            )
        )

        messages_table = dynamodb.Table(
            self, "IrisMessages",
            table_name="iris-messages",
            partition_key=dynamodb.Attribute(
                name="conversation_id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="message_id",
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl"
        )

        # Add GSI for querying messages by timestamp (for pagination)
        messages_table.add_global_secondary_index(
            index_name="conversation_id-timestamp-index",
            partition_key=dynamodb.Attribute(
                name="conversation_id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.NUMBER
            )
        )

        # Create Lambda Layer for shared utilities
        lambda_functions_path = os.path.join(os.path.dirname(__file__), "..", "lambda_functions")

        shared_layer = lamb.LayerVersion(
            self, "IrisLambdaLayerVersion",
            removal_policy=RemovalPolicy.RETAIN,
            code=lamb.Code.from_asset(os.path.join(lambda_functions_path, "shared")),
            compatible_architectures=[lamb.Architecture.X86_64, lamb.Architecture.ARM_64],
            description="Shared utilities with requests library v1.1"
        )

        # Environment variables shared across all Lambda functions
        shared_environment = {
            "USER_POOL_ID": existing_user_pool_id,
            "USER_POOL_CLIENT_ID": existing_user_pool_client_id,
            "IDENTITY_POOL_ID": existing_identity_pool_id,
            "STATIC_BUCKET": static_bucket.bucket_name,
            "USER_BUCKET": user_bucket.bucket_name,
            "CONNECTIONS_TABLE": connections_table.table_name,
            "CHAT_SESSIONS_TABLE": chat_sessions_table.table_name,
            "CONVERSATIONS_TABLE": conversations_table.table_name,
            "MESSAGES_TABLE": messages_table.table_name,
        }

        # Create Cognito Authorizer for API Gateway
        cognito_authorizer = apigateway.CognitoUserPoolsAuthorizer(
            self, "IrisCognitoAuthorizer",
            cognito_user_pools=[iris_cognito_user_pool],
            authorizer_name="IrisUserPoolAuthorizer",
            identity_source="method.request.header.Authorization"
        )

        # Create API Gateway REST API
        iris_backend = apigateway.RestApi(
            self, "IrisBackendApi",
            rest_api_name="Iris Backend API",
            description="Backend API for Iris application with Lambda integrations and Cognito authentication",
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,
                allow_methods=apigateway.Cors.ALL_METHODS,
                allow_headers=["Content-Type", "Authorization", "*"]
            )
        )

        # Create API Gateway WebSocket API for real-time AI inference
        websocket_api = apigatewayv2.WebSocketApi(
            self, "IrisWebSocketApi",
            api_name="Iris WebSocket API",
            description="WebSocket API for real-time AI inference with streaming responses"
        )

        # Create WebSocket stage
        websocket_stage = apigatewayv2.WebSocketStage(
            self, "IrisWebSocketStage",
            web_socket_api=websocket_api,
            stage_name="prod",
            auto_deploy=True
        )

        # Update environment variables with WebSocket endpoint
        shared_environment["WEBSOCKET_API_ENDPOINT"] = f"https://{websocket_api.api_id}.execute-api.{self.region}.amazonaws.com/prod"

        # Import NativeFunction from IrisNativeBackend-Stack
        # Note: Adjust the function name pattern if needed based on the actual function name in the other stack
        native_function_arn = f"arn:aws:lambda:{self.region}:{self.account}:function:NativeFunction"

        native_function = lamb.Function.from_function_arn(
            self, "ImportedNativeFunction",
            function_arn=native_function_arn
        )

        # Define endpoint mappings - declarative approach for easy expansion
        endpoint_mappings = [
            {
                "function_dir": "health_check",
                "lambda_name": "IrisLambda-pong",
                "api_path": "pong",
                "methods": ["GET"]
            },
            {
                "function_dir": "course_roster",
                "lambda_name": "IrisLambda-course-roster",
                "api_path": "roster_classes",
                "sub_resources": ["{term}", "{subject}"],
                "methods": ["GET"]
            },
            {
                "function_dir": "degree_programs",
                "lambda_name": "IrisLambda-degree-programs",
                "api_path": "list-degrees",
                "methods": ["GET"]
            },
            {
                "function_dir": "inference",
                "lambda_name": "IrisLambda-inference",
                "api_path": "inference",
                "methods": ["POST"]
            },
            {
                "function_dir": "degree_requirements",
                "lambda_name": "IrisLambda-degree-requirements",
                "api_path": "degree-requirements",
                "methods": ["GET"]
            },
            {
                "function_dir": "schedule_data",
                "lambda_name": "IrisLambda-schedule-data",
                "api_path": "grail",
                "sub_resources": ["{term}"],
                "methods": ["GET"]
            },
            {
                "function_dir": "external",  # Special marker for external function
                "lambda_name": "ImportedNativeFunction",
                "api_path": "native",
                "methods": ["POST"],
                "external_function": True
            },
            {
                "function_dir": "conversation_history",
                "lambda_name": "IrisLambda-conversation-history",
                "api_path": "conversations",
                "methods": ["GET", "POST"]
            },
            {
                "function_dir": "conversation_history",
                "lambda_name": "IrisLambda-conversation-history-id",
                "api_path": "conversations",
                "sub_resources": ["{id}"],
                "methods": ["GET", "PUT", "DELETE"],
                "reuse_function": True
            },
            {
                "function_dir": "conversation_history",
                "lambda_name": "IrisLambda-conversation-history-messages",
                "api_path": "conversations",
                "sub_resources": ["{id}", "messages"],
                "methods": ["POST"],
                "reuse_function": True
            }
        ]

        # Store created functions and resources to reuse them
        created_functions = {}
        created_resources = {}

        # Create Lambda functions and API Gateway integrations
        for mapping in endpoint_mappings:
            # Check if this is an external function
            if mapping.get("external_function", False):
                # Use the pre-imported external function
                lambda_function = native_function
            elif mapping.get("reuse_function", False):
                # Reuse an existing function
                base_function_name = f"IrisLambda-{mapping['function_dir'].replace('_', '-')}"
                if base_function_name in created_functions:
                    lambda_function = created_functions[base_function_name]
                else:
                    raise ValueError(f"Cannot reuse function {base_function_name} - not found in created functions")
            else:
                function_path = os.path.join(lambda_functions_path, mapping["function_dir"])

                # Create Lambda function
                lambda_function = lamb.Function(
                    self, mapping["lambda_name"],
                    runtime=lamb.Runtime.PYTHON_3_12,
                    handler="handler.lambda_handler",
                    code=lamb.Code.from_asset(function_path),
                    timeout=Duration.seconds(30),
                    memory_size=256,
                    environment=shared_environment,
                    layers=[shared_layer]
                )

                # Store the function for potential reuse
                created_functions[mapping["lambda_name"]] = lambda_function

                # Grant Lambda permissions to access S3 buckets
                static_bucket.grant_read(lambda_function)
                user_bucket.grant_read_write(lambda_function)

                # Grant Bedrock permissions specifically for the inference function
                if mapping["function_dir"] == "inference":
                    lambda_function.add_to_role_policy(
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "bedrock:InvokeModel",
                                "bedrock:InvokeModelWithResponseStream"
                            ],
                            resources=[
                                f"arn:aws:bedrock:*:*:inference-profile/*",
                                f"arn:aws:bedrock:*:*:foundation-model/*"
                            ]
                        )
                    )
                    # Grant DynamoDB permissions for conversation saving
                    conversations_table.grant_read_write_data(lambda_function)
                    messages_table.grant_read_write_data(lambda_function)

                # Grant DynamoDB permissions for conversation history function
                if mapping["function_dir"] == "conversation_history":
                    conversations_table.grant_read_write_data(lambda_function)
                    messages_table.grant_read_write_data(lambda_function)
                    chat_sessions_table.grant_read_write_data(lambda_function)
                    connections_table.grant_read_write_data(lambda_function)

            # Create API Gateway resource structure
            if mapping["api_path"] in created_resources:
                current_resource = created_resources[mapping["api_path"]]
            else:
                current_resource = iris_backend.root.add_resource(mapping["api_path"])
                created_resources[mapping["api_path"]] = current_resource

            # Add sub-resources if specified (for path parameters like {term}, {subject})
            if "sub_resources" in mapping:
                resource_path = mapping["api_path"]
                for sub_resource in mapping["sub_resources"]:
                    resource_path += f"/{sub_resource}"
                    if resource_path in created_resources:
                        current_resource = created_resources[resource_path]
                    else:
                        current_resource = current_resource.add_resource(sub_resource)
                        created_resources[resource_path] = current_resource

            # Create Lambda integration
            lambda_integration = apigateway.LambdaIntegration(
                lambda_function,
                request_templates={"application/json": '{"statusCode": "200"}'}
            )

            # Add specified HTTP methods with appropriate authorization
            for method in mapping["methods"]:
                current_resource.add_method(
                    method,
                    lambda_integration,
                    authorizer=cognito_authorizer,
                    authorization_type=apigateway.AuthorizationType.COGNITO
                )

            # Create async version for native endpoint
            if mapping["api_path"] == "native":
                # Create async resource
                async_resource = iris_backend.root.add_resource(mapping["api_path"] + "-async")

                # Create async Lambda integration using AWS integration for full control
                async_lambda_integration = apigateway.AwsIntegration(
                    service="lambda",
                    path=f"2015-03-31/functions/{lambda_function.function_arn}/invocations",
                    integration_http_method="POST",
                    options=apigateway.IntegrationOptions(
                        credentials_role=iam.Role(
                            self, "ApiGatewayLambdaAsyncRole",
                            assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"),
                            inline_policies={
                                "InvokeLambda": iam.PolicyDocument(
                                    statements=[
                                        iam.PolicyStatement(
                                            effect=iam.Effect.ALLOW,
                                            actions=["lambda:InvokeFunction"],
                                            resources=[lambda_function.function_arn]
                                        )
                                    ]
                                )
                            }
                        ),
                        request_parameters={
                            "integration.request.header.X-Amz-Invocation-Type": "'Event'"
                        },
                        integration_responses=[
                            apigateway.IntegrationResponse(
                                status_code="202",
                                response_templates={"application/json": '{"message": "Request accepted for async processing"}'}
                            )
                        ]
                    )
                )

                # Add methods to async endpoint
                for method in mapping["methods"]:
                    async_resource.add_method(
                        method,
                        async_lambda_integration,
                        authorizer=cognito_authorizer,
                        authorization_type=apigateway.AuthorizationType.COGNITO,
                        method_responses=[
                            apigateway.MethodResponse(
                                status_code="202",
                                response_models={"application/json": apigateway.Model.EMPTY_MODEL}
                            )
                        ]
                    )

        # Note: For external functions, permissions must be granted manually on the source function
        # The external Lambda function needs a resource-based policy allowing this API Gateway to invoke it
        # You can add this via AWS CLI:
        # aws lambda add-permission --function-name NativeFunction --statement-id api-gateway-invoke \
        #   --action lambda:InvokeFunction --principal apigateway.amazonaws.com \
        #   --source-arn "arn:aws:execute-api:REGION:ACCOUNT:API-ID/*/*"

        # ===================================
        # WEBSOCKET LAMBDA FUNCTIONS
        # ===================================

        # Create WebSocket connection handler Lambda
        websocket_connect_function = lamb.Function(
            self, "IrisWebSocketConnect",
            runtime=lamb.Runtime.PYTHON_3_12,
            handler="handler.lambda_handler",
            code=lamb.Code.from_asset(os.path.join(lambda_functions_path, "websocket_connect")),
            timeout=Duration.seconds(30),
            memory_size=256,
            environment=shared_environment,
            layers=[shared_layer]
        )

        # Create WebSocket disconnect handler Lambda
        websocket_disconnect_function = lamb.Function(
            self, "IrisWebSocketDisconnect",
            runtime=lamb.Runtime.PYTHON_3_12,
            handler="handler.lambda_handler",
            code=lamb.Code.from_asset(os.path.join(lambda_functions_path, "websocket_disconnect")),
            timeout=Duration.seconds(30),
            memory_size=256,
            environment=shared_environment,
            layers=[shared_layer]
        )

        # Create WebSocket message handler Lambda (for inference)
        websocket_message_function = lamb.Function(
            self, "IrisWebSocketMessage",
            runtime=lamb.Runtime.PYTHON_3_12,
            handler="handler.lambda_handler",
            code=lamb.Code.from_asset(os.path.join(lambda_functions_path, "websocket_message")),
            timeout=Duration.seconds(900),  # 15 minutes for long AI responses
            memory_size=512,
            environment=shared_environment,
            layers=[shared_layer]
        )

        # Grant DynamoDB permissions to WebSocket functions
        connections_table.grant_read_write_data(websocket_connect_function)
        connections_table.grant_read_write_data(websocket_disconnect_function)
        connections_table.grant_read_write_data(websocket_message_function)

        chat_sessions_table.grant_read_write_data(websocket_connect_function)
        chat_sessions_table.grant_read_write_data(websocket_disconnect_function)
        chat_sessions_table.grant_read_write_data(websocket_message_function)

        # Grant S3 permissions to WebSocket functions
        static_bucket.grant_read(websocket_connect_function)
        static_bucket.grant_read(websocket_disconnect_function)
        static_bucket.grant_read(websocket_message_function)

        user_bucket.grant_read_write(websocket_connect_function)
        user_bucket.grant_read_write(websocket_disconnect_function)
        user_bucket.grant_read_write(websocket_message_function)

        # Grant Bedrock permissions to WebSocket message function
        websocket_message_function.add_to_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream"
                ],
                resources=[
                    f"arn:aws:bedrock:*:*:inference-profile/*",
                    f"arn:aws:bedrock:*:*:foundation-model/*"
                ]
            )
        )

        # Grant permissions for WebSocket API management
        websocket_policy = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["execute-api:ManageConnections"],
            resources=[f"arn:aws:execute-api:{self.region}:{self.account}:{websocket_api.api_id}/*/*"]
        )

        websocket_connect_function.add_to_role_policy(websocket_policy)
        websocket_disconnect_function.add_to_role_policy(websocket_policy)
        websocket_message_function.add_to_role_policy(websocket_policy)

        # Create WebSocket integrations using CDK v2 syntax
        connect_integration = apigatewayv2.CfnIntegration(
            self, "ConnectIntegration",
            api_id=websocket_api.api_id,
            integration_type="AWS_PROXY",
            integration_uri=f"arn:aws:apigateway:{self.region}:lambda:path/2015-03-31/functions/{websocket_connect_function.function_arn}/invocations",
            integration_method="POST"
        )

        disconnect_integration = apigatewayv2.CfnIntegration(
            self, "DisconnectIntegration",
            api_id=websocket_api.api_id,
            integration_type="AWS_PROXY",
            integration_uri=f"arn:aws:apigateway:{self.region}:lambda:path/2015-03-31/functions/{websocket_disconnect_function.function_arn}/invocations",
            integration_method="POST"
        )

        message_integration = apigatewayv2.CfnIntegration(
            self, "MessageIntegration",
            api_id=websocket_api.api_id,
            integration_type="AWS_PROXY",
            integration_uri=f"arn:aws:apigateway:{self.region}:lambda:path/2015-03-31/functions/{websocket_message_function.function_arn}/invocations",
            integration_method="POST"
        )

        # Add routes to WebSocket API using CfnRoute
        connect_route = apigatewayv2.CfnRoute(
            self, "ConnectRoute",
            api_id=websocket_api.api_id,
            route_key="$connect",
            authorization_type="NONE",
            operation_name="ConnectRoute",
            target=f"integrations/{connect_integration.ref}"
        )

        disconnect_route = apigatewayv2.CfnRoute(
            self, "DisconnectRoute",
            api_id=websocket_api.api_id,
            route_key="$disconnect",
            authorization_type="NONE",
            operation_name="DisconnectRoute",
            target=f"integrations/{disconnect_integration.ref}"
        )

        message_route = apigatewayv2.CfnRoute(
            self, "MessageRoute",
            api_id=websocket_api.api_id,
            route_key="inference",
            authorization_type="NONE",
            operation_name="MessageRoute",
            target=f"integrations/{message_integration.ref}"
        )

        # Grant API Gateway permission to invoke Lambda functions
        websocket_connect_function.add_permission(
            "ApiGatewayInvokeConnect",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"arn:aws:execute-api:{self.region}:{self.account}:{websocket_api.api_id}/*/*"
        )

        websocket_disconnect_function.add_permission(
            "ApiGatewayInvokeDisconnect",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"arn:aws:execute-api:{self.region}:{self.account}:{websocket_api.api_id}/*/*"
        )

        websocket_message_function.add_permission(
            "ApiGatewayInvokeMessage",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn=f"arn:aws:execute-api:{self.region}:{self.account}:{websocket_api.api_id}/*/*"
        )

        # Output important values for reference
        CfnOutput(
            self, "ApiGatewayUrl",
            value=iris_backend.url,
            description="API Gateway endpoint URL"
        )

        CfnOutput(
            self, "UserPoolId",
            value=existing_user_pool_id,
            description="Cognito User Pool ID"
        )

        CfnOutput(
            self, "UserPoolClientId",
            value=existing_user_pool_client_id,
            description="Cognito User Pool Client ID"
        )

        CfnOutput(self, "SharedBucketARN", value=static_bucket.bucket_arn, description="Shared Bucket ARN")
        CfnOutput(self, "UserBucketARN", value=user_bucket.bucket_arn, description="User Bucket ARN")

        CfnOutput(
            self, "IdentityPoolId",
            value=existing_identity_pool_id,
            description="Cognito Identity Pool ID"
        )

        CfnOutput(
            self, "NativeFunctionPermissionCommand",
            value=f'aws lambda add-permission --function-name NativeFunction --statement-id api-gateway-invoke-iris --action lambda:InvokeFunction --principal apigateway.amazonaws.com --source-arn "arn:aws:execute-api:{self.region}:{self.account}:{iris_backend.rest_api_id}/*/*"',
            description="Command to grant API Gateway permission to invoke NativeFunction"
        )

        CfnOutput(
            self, "AsyncEndpointInfo",
            value=f"{iris_backend.url}native-async",
            description="URL for async native endpoint (returns 202 and processes asynchronously)"
        )

        CfnOutput(
            self, "WebSocketApiUrl",
            value=f"wss://{websocket_api.api_id}.execute-api.{self.region}.amazonaws.com/{websocket_stage.stage_name}",
            description="WebSocket API endpoint URL for real-time AI inference"
        )

        CfnOutput(
            self, "ConnectionsTableName",
            value=connections_table.table_name,
            description="DynamoDB table for WebSocket connections"
        )

        CfnOutput(
            self, "ChatSessionsTableName",
            value=chat_sessions_table.table_name,
            description="DynamoDB table for chat sessions"
        )

        CfnOutput(
            self, "ConversationsTableName",
            value=conversations_table.table_name,
            description="DynamoDB table for conversation metadata"
        )

        CfnOutput(
            self, "MessagesTableName",
            value=messages_table.table_name,
            description="DynamoDB table for conversation messages"
        )
