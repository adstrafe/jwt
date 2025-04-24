import { expect } from 'chai';
import { Header, issueToken, UserPayload, verifyToken } from '..';
import { encodeBase64, decodeBase64, hmacSign } from '../crypto';
import { JwtError } from '../JwtError';
import { readFileSync } from 'fs';
import { join } from 'path';

const PRIVATE_KEY = readFileSync(join(__dirname, 'keys', 'private.pem'), 'utf8');
const PUBLIC_KEY = readFileSync(join(__dirname, 'keys', 'public.pem'), 'utf8');

describe('Crypto', () => {
	it('encodes a string into Base64URL', () => {
		const input = 'Hello, World!';
		const encoded = encodeBase64(input);
		expect(encoded).to.be.a('string');
		expect(encoded).to.not.include('=').to.not.include('+').to.not.include('/');
		expect(decodeBase64(encoded).toString('utf8')).to.equal(input);
	});

	it('encodes a Buffer into Base64URL', () => {
		const input = Buffer.from('Hello, World!', 'utf8');
		const encoded = encodeBase64(input);
		expect(encoded).to.be.a('string');
		expect(encoded).to.not.include('=').to.not.include('+').to.not.include('/');
		expect(decodeBase64(encoded).toString('utf8')).to.equal(input.toString('utf8'));
	});

	it('handles empty input', () => {
		const input = '';
		const encoded = encodeBase64(input);
		expect(encoded).to.equal('');
		expect(decodeBase64(encoded).toString('utf8')).to.equal(input);
	});
});

describe('Jwt library', () => {
	let token: string;
	const secret = 'y7N4xR9qK2pV8sT5mB1zL6wF3uD0hJcy7N4xR9qK2pV8sT5mB1zL6wF3uD0hJc';
	const expiryTimeMs = 5 * 60 * 1000; // 5 minutes

	const header: Header = {
		alg: 'HS256',
		typ: 'JWT',
	};

	const payload: UserPayload = {
		aud: 'userId1234',
		iss: 'jestId4321',
		roles: 'auth.login',
	};

	beforeEach(async () => {
		// Generate a fresh token before each test
		token = (await issueToken(header, payload, secret, expiryTimeMs)).token;
	});

	describe('issueToken', () => {
		it('signs a payload and header into a token string', async () => {
			expect(token).to.be.a('string', `Token: ${token}`);
			expect(token.split('.')).to.have.lengthOf(3);
			expect(token).to.not.include('=').to.not.include('+').to.not.include('/');

			const [ headerBase64, payloadBase64 ] = token.split('.');
			const decodedHeader = JSON.parse(decodeBase64(headerBase64).toString('utf8'));
			expect(decodedHeader).to.deep.equal(header);

			const decodedPayload = JSON.parse(decodeBase64(payloadBase64).toString('utf8'));
			expect(decodedPayload.aud).to.equal(payload.aud);
			expect(decodedPayload.iss).to.equal(payload.iss);
			expect(decodedPayload.roles).to.equal(payload.roles);
			expect(decodedPayload.iat).to.be.a('number');
			expect(decodedPayload.exp).to.be.a('number');
			expect(decodedPayload.exp - decodedPayload.iat).to.equal(expiryTimeMs);
		});

		it('throws for unsupported algorithms', async () => {
			const invalidHeader: Header = { alg: 'INVALID' as any, typ: 'JWT' };
			try {
				await issueToken(invalidHeader, payload, secret, expiryTimeMs);
				expect.fail('Expected issueToken to throw an error');
			} catch (error: any) {
				expect(error).to.be.instanceOf(JwtError);
				expect(error.message).to.equal('Unsupported algorithm INVALID');
			}
		});

		it('throws for invalid HMAC secret length', async () => {
			const shortSecret = 'short';
			try {
				await issueToken(header, payload, shortSecret, expiryTimeMs);
				expect.fail('Expected issueToken to throw an error');
			} catch (error: any) {
				expect(error).to.be.instanceOf(JwtError);
				expect(error.message).to.include('Secret too short');
			}
		});

		it('signs a token with RS256', async () => {
			const rsaHeader: Header = { alg: 'RS256', typ: 'JWT' };
			const privateKey = `${PRIVATE_KEY}`;
			const token = (await issueToken(rsaHeader, payload, privateKey, expiryTimeMs)).token;
			expect(token).to.be.a('string');
			expect(token.split('.')).to.have.lengthOf(3);
			expect(token).to.not.include('=').to.not.include('+').to.not.include('/');
	
			const [headerBase64, payloadBase64] = token.split('.');
			const decodedHeader = JSON.parse(decodeBase64(headerBase64).toString('utf8'));
			expect(decodedHeader).to.deep.equal(rsaHeader);
		});
	
		it('throws for invalid RSA private key', async () => {
			const rsaHeader: Header = { alg: 'RS256', typ: 'JWT' };
			const invalidKey = 'not-a-key';
			try {
				await issueToken(rsaHeader, payload, invalidKey, expiryTimeMs);
				expect.fail('Expected issueToken to throw an error');
			} catch (error: any) {
				expect(error).to.be.instanceOf(JwtError);
				expect(error.message).to.include('Invalid private key');
			}
		});
	});

	describe('verifyToken', () => {
		it('verifies a valid token', () => {
			expect(() =>
				verifyToken(token, { algorithm: header.alg, secret })
			).to.not.throw();
		});

		it('throws for expired token', async () => {
			const expiredToken = (await issueToken(header, payload, secret, -1000)).token;
			expect(() =>
				verifyToken(expiredToken, { algorithm: header.alg, secret })
			).to.throw(JwtError, 'Token expired');
		});

		it('throws for incorrect secret', () => {
			expect(() =>
				verifyToken(token, { algorithm: header.alg, secret: 'wrong-secret' })
			).to.throw(JwtError, 'Jwt malformed');
		});

		it('throws for algorithm mismatch', () => {
			expect(() =>
				verifyToken(token, { algorithm: 'HS512', secret })
			).to.throw(JwtError, 'Algorithm mismatch');
		});

		it('throws for malformed token', () => {
			const malformedToken = 'invalid.token.signature';
			expect(() =>
				verifyToken(malformedToken, { algorithm: header.alg, secret })
			).to.throw(JwtError, 'JWT is not correctly Base64URL‑encoded');
		});

		it('throws for alg: none', async () => {
			const noneHeader = { alg: 'none' as any, typ: 'JWT' };
			const base64header = encodeBase64(JSON.stringify(noneHeader));
			const base64payload = encodeBase64(
				JSON.stringify({ ...payload, iat: Date.now(), exp: Date.now() + expiryTimeMs })
			);
			const tamperedToken = `${base64header}.${base64payload}.`; // Empty signature
			expect(() =>
				verifyToken(tamperedToken, { algorithm: header.alg, secret })
			).to.throw(JwtError, 'JWT is not correctly Base64URL‑encoded.'); // Should fail on encoding check since signature is missing
		});

		it('throws for invalid typ', async () => {
			const invalidHeader = { alg: 'HS256', typ: 'INVALID' };
			const base64header = encodeBase64(JSON.stringify(invalidHeader));
			const [_, payloadBase64, signature] = token.split('.');
			const tamperedToken = `${base64header}.${payloadBase64}.${signature}`;
			expect(() =>
				verifyToken(tamperedToken, { algorithm: header.alg, secret })
			).to.throw(JwtError, 'Invalid header: Expected typ "JWT", got "INVALID"');
		});

		it('throws for unexpected header fields', async () => {
			const tamperedHeader = { alg: 'HS256', typ: 'JWT', kid: 'malicious' };
			const base64header = encodeBase64(JSON.stringify(tamperedHeader));
			const [_, payloadBase64, signature] = token.split('.');
			const tamperedToken = `${base64header}.${payloadBase64}.${signature}`;
			expect(() =>
				verifyToken(tamperedToken, { algorithm: header.alg, secret })
			).to.throw(JwtError, 'Invalid header: Unexpected fields present');
		});

		it('throws for invalid Base64URL segment', () => {
			const invalidToken = 'invalid+=.token.signature'; // Invalid Base64URL with += characters
			expect(() =>
				verifyToken(invalidToken, { algorithm: header.alg, secret })
			).to.throw(JwtError, 'JWT is not correctly Base64URL‑encoded');
		});

		it('throws for missing exp claim', async () => {
			const base64header = encodeBase64(JSON.stringify(header));
			const base64payload = encodeBase64(JSON.stringify({ ...payload, iat: Date.now() }));
			const unsignedToken = `${base64header}.${base64payload}`;
			const signature = hmacSign(unsignedToken, secret, 'SHA256');
			const invalidToken = `${unsignedToken}.${signature}`;
			expect(() =>
				verifyToken(invalidToken, { algorithm: header.alg, secret })
			).to.throw(JwtError, 'Invalid payload: Missing or invalid exp claim');
		});

		it('throws for empty signature', async () => {
			const [headerBase64, payloadBase64] = token.split('.');
			const invalidToken = `${headerBase64}.${payloadBase64}.`;
			expect(() =>
				verifyToken(invalidToken, { algorithm: header.alg, secret })
			).to.throw(JwtError, 'JWT is not correctly Base64URL‑encoded');
		});

		it('verifies a valid RS256 token', async () => {
			const rsaHeader: Header = { alg: 'RS256', typ: 'JWT' };
			const privateKey = `${PRIVATE_KEY}`;
			const publicKey = `${PUBLIC_KEY}`;
			const token = (await issueToken(rsaHeader, payload, privateKey, expiryTimeMs)).token;
			expect(() =>
				verifyToken(token, { algorithm: 'RS256', secret: publicKey })
			).to.not.throw();
		});
	});
});

