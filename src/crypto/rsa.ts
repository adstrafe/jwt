import { createSign } from 'node:crypto';
import type { Secret } from '../index.js';
import { JwtError } from '../JwtError.js';
import { encodeBase64 } from './base64.js';

/**
 * Signs data using RSA with the specified algorithm.
 * 
 * @param data - The data to sign (usually the base64-encoded header and payload).
 * @param privateKey - The private key to sign the data.
 * @param algorithm - The RSA signing algorithm to use ('SHA256', 'SHA384', or 'SHA512').
 * @returns The RSA signature in base64 encoding.
 */
export async function rsaSign(data: string, privateKey: Secret, algorithm: 'SHA256' | 'SHA384' | 'SHA512'): Promise<string> {
	return new Promise((resolve, reject) => {
		try {
			const sign = createSign(algorithm);
			sign.update(data);
			const signature = encodeBase64(sign.sign(privateKey));
			resolve(signature);
		} catch (error: any) {
			reject(new JwtError(`RSA signing failed ${error.message}`, error));
		}
	});
}