import { APIGatewayAuthorizerResult, APIGatewayTokenAuthorizerEvent } from 'aws-lambda';
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

export const handler = async (event: APIGatewayTokenAuthorizerEvent): Promise<APIGatewayAuthorizerResult> => {
    // Extract the bearer authorization token from the event
    const authHeader = event.authorizationToken;
    const token = authHeader.split(' ')[1]!;

    // Load the JWKS (JSON Web Key Set) from the well-known endpoint
    const jwksUrl = 'https://example.com/.well-known/jwks.json';
    const client = jwksClient({ jwksUri: jwksUrl });

    try {
        // decode the token to get the kid
        const kid = jwt.decode(token, { complete: true })?.['header']['kid'];
        // get the public key from the JWKS
        const key = await client.getSigningKey(kid);
        // verify the token
        jwt.verify(token, key.getPublicKey());
    } catch (err) {
        console.error('Error verifying token', err);
        // Return an authorization response indicating the request is not authorized
        return {
            principalId: 'user',
            policyDocument: {
                Version: '2012-10-17',
                Statement: [
                    {
                        Action: 'execute-api:Invoke',
                        Effect: 'Deny',
                        Resource: event.methodArn,
                    },
                ],
            },
        };
    }

    // return an authorization response indicating the request is authorized
    return {
        principalId: 'user',
        policyDocument: {
            Version: '2012-10-17',
            Statement: [
                {
                    Action: 'execute-api:Invoke',
                    Effect: 'Allow',
                    Resource: event.methodArn,
                },
            ],
        },
    };
};
