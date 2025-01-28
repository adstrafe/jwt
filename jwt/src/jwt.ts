import { hmacSign, ecdsaSign, rsaSign, encodeBase64 } from './crypto';
import { JwtError } from './JwtError';

export type Signature = string;
/**
 * Supported algorithms for signing and verifying JWTs.
 * @value 'HS256' HMAC using SHA-256
 * @value 'HS384' HMAC using SHA-384
 * @value 'HS512' HMAC using SHA-512
 * @value 'RS256' RSA using SHA-256
 * @value 'RS384' RSA using SHA-384
 * @value 'RS512' RSA using SHA-512
 * @value 'ES256' ECDSA using P-256 and SHA-256
 * @value 'ES384' ECDSA using P-384 and SHA-384
 * @value 'ES512' ECDSA using P-521 and SHA-512
 */
export type Algorithm =
	'HS256' |
	'HS384' |
	'HS512' |
	'RS256' |
	'RS384' |
	'RS512' |
	'ES256' |
	'ES384' |
	'ES512'

/**
 * The "typ" (type) claim specifies the type of JWT, indicating how the JWT is used.
 * @enum JwtTypes
 */
export enum JwtTypes {
	/** JWT - JSON Web Token
	 * @value JWT
	 * @example 'JWT'
	*/
	JWT,
	/** JOSE - JSON Object Signing and Encryption
	 * @value JOSE
	 * @example 'JOSE'
	*/
	JOSE,
	/** JWE - JSON Web Encryption
	 * @value JWE
	 * @example 'JWE'
	*/
	JWE
}

/**
 * The "cty" (content type) claim specifies the content type of the JWT.
 * 
 * @enum JwtContentTypes
 */
export enum JwtContentTypes {
	/** application/json - The content is a JSON object
	 * @value JSON
	 * @example 'application/json'
	*/
	JSON = 'application/json',
	/** JWT - The content is another JWT
	 * @value JWT
	 * @example 'JWT'
	*/
	JWT = 'JWT'
}

/**
 * Represents the JWT header, which contains information about the algorithm
 * and other optional metadata related to the JWT.
 * 
 * @interface Header
 */
export interface Header {
	/**
	 * The "alg" (algorithm) claim specifies the cryptographic algorithm 
	 * used to sign or encrypt the JWT.
	 * Supported algorithms include HMAC, RSA, ECDSA, and "none" for unsecured tokens.
	 * 
	 * @see Algorithm for the list of supported values.
	 */
	readonly alg: Algorithm;

	/**
	 * The "typ" (type) claim declares the media type of the JWT.
	 * 
	 * This is used by JWT applications when the object is part of a data structure
	 * that can contain different types of objects (e.g., when distinguishing between
	 * a JWT and other types). It is OPTIONAL and is typically set to "JWT" to indicate
	 * that the object is a JWT.
	 * 
	 * @example 'JWT'
	 * @value JwtTypes | string
	 */
	readonly typ?: JwtTypes | string;

	/**
	 * The "cty" (content type) claim provides structural information about the JWT,
	 * especially when nested signing or encryption operations are used.
	 * 
	 * If nested operations are not employed, this is NOT RECOMMENDED. If nested operations
	 * are used, this MUST be present and set to "JWT" to indicate that the JWT carries another JWT.
	 * 
	 * @example 'JWT'
	 * @value JwtContentTypes | string
	 */
	readonly cty?: JwtContentTypes | string;
}


/**
 * Represents the payload of the JWT, which contains claims about the entity
 * that the JWT is describing (usually the user) and additional metadata.
 * 
 * The claims can be registered claims, public claims, or private claims.
 * Registered claims are predefined by the JWT specification, while public
 * and private claims are user-defined and can carry specific information
 * as needed by the application.
 * 
 * @interface Payload
 * @template T - Custom type for additional claims (defaults to `Record<string, unknown>`).
 */
export interface Payload<T = Record<string, unknown>> {
	/**
	 * The "iss" (issuer) claim identifies the principal that issued the JWT.
	 * This claim is typically application-specific.
	 * 
	 * @example 'https://example.com'
	 * @value string
	 */
	readonly iss?: string;

	/**
	 * The "sub" (subject) claim identifies the principal that is the subject of the JWT.
	 * The claims in a JWT are normally statements about the subject, and it is usually
	 * a unique identifier for the user or entity.
	 * 
	 * @example '12345'
	 * @value string
	 */
	readonly sub?: string;

	/**
	 * The "aud" (audience) claim identifies the recipients that the JWT is intended for.
	 * This can be an array or a single string containing the audience’s identifiers.
	 * 
	 * @example ['client1', 'client2']
	 * @value string | string[]
	 */
	readonly aud?: string | string[];

	/**
	 * The "exp" (expiration time) claim identifies the expiration time after which
	 * the JWT must not be accepted for processing.
	 * 
	 * @example 1640995200
	 * @value number (NumericDate)
	 */
	readonly exp?: number;

	/**
	 * The "nbf" (not before) claim identifies the time before which the JWT
	 * must not be accepted for processing.
	 * 
	 * @example 1640991600
	 * @value number (NumericDate)
	 */
	readonly nbf?: number;

	/**
	 * The "iat" (issued at) claim identifies the time at which the JWT was issued.
	 * It can be used to determine the age of the JWT.
	 * 
	 * @example 1640988000
	 * @value number (NumericDate)
	 */
	readonly iat?: number;

	/**
	 * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
	 * It can be used to prevent the JWT from being replayed.
	 * 
	 * @example 'jwt-123456'
	 * @value string
	 */
	readonly jti?: string;

	/**
	 * Allows adding custom claims to the JWT payload.
	 * 
	 * @example { customClaim: 'value' }
	 * @value { [key: string]: unknown | T }
	 */
	[key: string]: unknown | T;
}

/**
 * Signs a JWT token by encoding the header and payload as Base64URL
 * and applying the specified algorithm from the header.
 *
 * @param header - The JWT header object, including the signing algorithm.
 * @param payload - The JWT payload object, containing claims and data.
 * @param secret - The secret key used to sign the token.
 * @returns The signed JWT token as a string.
*/
export function issueToken(header: Header, payload: Payload, secret: string) {
	const { alg } = header;
	const base64header = encodeBase64(JSON.stringify(header));
	const base64payload = encodeBase64(JSON.stringify(payload));
	const unsignedToken = `${base64header}.${base64payload}`;

	let signature = '';
	switch (alg) {
		case 'HS256':
		case 'HS384':
		case 'HS512':
			signature = hmacSign(unsignedToken, secret, alg);
			break;

		case 'RS256':
		case 'RS384':
		case 'RS512':
			signature = rsaSign(unsignedToken, secret, alg);
			break;

		case 'ES256':
		case 'ES384':
		case 'ES512':
			signature = ecdsaSign(unsignedToken, secret, alg);
			break;

		default:
			throw new JwtError(`Unsupported algorithm ${alg}`);
	}

	return `${unsignedToken}.${signature}`;
}