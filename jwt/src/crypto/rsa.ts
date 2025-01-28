import { createSign } from 'node:crypto';
import { Algorithm } from 'src/jwt';

/**
 * Signs data using RSA with the specified algorithm.
 * 
 * @param data - The data to sign (usually the base64-encoded header and payload).
 * @param privateKey - The private key to sign the data.
 * @param algorithm - The RSA signing algorithm to use ('SHA256', 'SHA384', or 'SHA512').
 * @returns The RSA signature in base64 encoding.
 */
export function rsaSign(data: string, privateKey: string, algorithm: Algorithm) {
	const sign = createSign(algorithm);
	sign.update(data);
	return sign.sign(privateKey, 'base64');
}
