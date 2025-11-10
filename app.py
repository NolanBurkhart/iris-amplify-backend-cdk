#!/usr/bin/env python3

import aws_cdk as cdk

from iris_cdk_amplify.iris_cdk_amplify_stack import IrisCdkAmplifyStack


app = cdk.App()
IrisCdkAmplifyStack(app, "IrisCdkAmplifyStack")

app.synth()
