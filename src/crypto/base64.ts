export function encodeBase64(data: string | Buffer): string {
	const buffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;

	return buffer
		.toString('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '');
}

export function decodeBase64(data: string) {
	let paddedData = data
		.replace(/-/g, '+')
		.replace(/_/g, '/');

	while (paddedData.length % 4 !== 0) {
		paddedData += '=';
	}
	return Buffer.from(paddedData, 'base64');
}
