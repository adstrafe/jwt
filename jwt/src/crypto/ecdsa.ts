import { createSign, KeyObject } from 'node:crypto';
import type { Secret } from 'src/jwt';
import { JwtError } from 'src/JwtError';

/**
 * Signs data using ECDSA with the specified algorithm.
 * 
 * @param data - The data to sign (usually the base64-encoded header and payload).
 * @param privateKey - The private key to sign the data.
 * @param algorithm - The ECDSA signing algorithm to use ('ES256', 'ES384', or 'ES512').
 * @returns The ECDSA signature in base64 encoding.
 */
export async function ecdsaSign(data: string, privateKey: Secret, algorithm: 'ES256' | 'ES384' | 'ES512'): Promise<string> {
	return new Promise((resolve, reject) => {
		try {
			const sign = createSign(algorithm);
			sign.update(data);

			if (privateKey instanceof KeyObject) {
				privateKey = privateKey.export({type: 'pkcs8', format: 'pem'});
			}

			const signature = sign.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' }, 'base64');
			resolve(signature);
		}
		catch (error: any) {
			reject(new JwtError(`ECDSA signing failed ${error.message}`, error));
		}
	});
}