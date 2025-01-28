export function encodeBase64(input: string) {
	return Buffer.from(input)
		.toString('base64')
		.replace('/\+/g', '-')
		.replace('/\//g', '_')
		.replace('/=+$/', '');
}

export function decodeBase64(input: string) {
	const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
	const paddedBase64 = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, '=');

	return Buffer.from(paddedBase64, 'base64')
		.toString('utf-8');
}