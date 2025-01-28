import { createSign } from 'node:crypto';

/**
 * Signs data using ECDSA with the specified algorithm.
 * 
 * @param data - The data to sign (usually the base64-encoded header and payload).
 * @param privateKey - The private key to sign the data.
 * @param algorithm - The ECDSA signing algorithm to use ('ES256', 'ES384', or 'ES512').
 * @returns The ECDSA signature in base64 encoding.
 */
export function ecdsaSign(data: string, privateKey: string, algorithm: 'ES256' | 'ES384' | 'ES512') {
	const sign = createSign(algorithm);
	sign.update(data);
	return sign.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' }, 'base64');
}
