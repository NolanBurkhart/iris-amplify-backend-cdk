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
    aws_amplify as amplify,
    aws_lambda as lamb,
    aws_s3 as s3,
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
                "methods": ["GET"]
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
            }
        ]

        # Create Lambda functions and API Gateway integrations
        for mapping in endpoint_mappings:
            function_path = os.path.join(lambda_functions_path, mapping["function_dir"])

            # Create Lambda function
            lambda_function = lamb.Function(
                self, mapping["lambda_name"],
                runtime=lamb.Runtime.PYTHON_3_9,
                handler="handler.lambda_handler",
                code=lamb.Code.from_asset(function_path),
                timeout=Duration.seconds(30),
                memory_size=256,
                environment=shared_environment,
                layers=[shared_layer]
            )

            # Grant Lambda permissions to access S3 buckets
            static_bucket.grant_read(lambda_function)
            user_bucket.grant_read_write(lambda_function)

            # Create API Gateway resource structure
            current_resource = iris_backend.root.add_resource(mapping["api_path"])

            # Add sub-resources if specified (for path parameters like {term}, {subject})
            if "sub_resources" in mapping:
                for sub_resource in mapping["sub_resources"]:
                    current_resource = current_resource.add_resource(sub_resource)

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
