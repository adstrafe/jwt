import { createHmac } from 'node:crypto';
import type { Secret } from 'src/jwt';

/**
 * Signs data using HMAC with the specified algorithm.
 * 
 * @param data - The data to sign (usually the base64-encoded header and payload).
 * @param secret - The secret key to sign the data.
 * @param algorithm - The HMAC algorithm to use ('SHA256', 'SHA384', or 'SHA512').
 * @returns The HMAC signature in base64 encoding.
 */
export function hmacSign(data: string, secret: Secret, algorithm: 'SHA256' | 'SHA384' | 'SHA512'): string {
	const hmac = createHmac(algorithm, secret);
	hmac.update(data);

	return hmac.digest('base64');
}
