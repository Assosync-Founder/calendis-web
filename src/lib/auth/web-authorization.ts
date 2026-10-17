import 'server-only';

import { createHash, randomBytes } from 'node:crypto';
import Env from '@/config/env';
import redis from '@/services/redis/redis.server';
import type {
	IdentityTicketResponse,
	WebAuthenticationTransaction,
	WebSsoEndpoints
} from '@/types/auth';

const createSecret = (): string => {
	return randomBytes(32).toString('base64url');
};

const createHashValue = (value: string): string => {
	return createHash('sha256').update(value, 'utf8').digest('base64url');
};

const isIdentityTicketResponse = (
	value: unknown
): value is IdentityTicketResponse => {
	return (
		typeof value === 'object' &&
		value !== null &&
		'identityTicket' in value &&
		typeof value.identityTicket === 'string' &&
		'expiresAt' in value &&
		typeof value.expiresAt === 'string'
	);
};

/** Starts a discoverable-passkey SSO transaction with Assosync Account.
 * @returns Account authorization URL and local browser transaction token.
 */
const startPasskeyWebAuthorization = async (
	endpoints: WebSsoEndpoints
): Promise<{
	readonly authorizationUrl: string;
	readonly transactionId: string;
}> => {
	const clientSecret = Env.private.webSso.authWebClientSecret;

	if (!clientSecret) {
		throw new Error('The Calendis Web SSO configuration is incomplete.');
	}

	const transactionId = createSecret();
	const state = createSecret();
	const codeVerifier = createSecret();
	const codeChallenge = createHashValue(codeVerifier);
	const transaction: WebAuthenticationTransaction = {
		state,
		codeVerifier,
		redirectUri: endpoints.redirectUri,
		returnTo: '/'
	};

	await redis.set(
		`auth:web:transactions:${createHashValue(transactionId)}`,
		JSON.stringify(transaction),
		{ px: 10 * 60_000, nx: true }
	);

	const response = await fetch(
		`${endpoints.accountUrl}/api/auth/passkeys/web/identity`,
		{
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			cache: 'no-store',
			body: JSON.stringify({
				clientId: 'calendis',
				clientSecret,
				redirectUri: endpoints.redirectUri,
				state,
				codeChallenge
			})
		}
	);
	const result: unknown = await response.json();

	if (!response.ok || !isIdentityTicketResponse(result)) {
		throw new Error('Passkey authentication could not be started.');
	}

	const authorizationUrl = new URL(
		'/api/auth/web/authorize',
		endpoints.accountUrl
	);

	authorizationUrl.searchParams.set('identity_ticket', result.identityTicket);

	return {
		authorizationUrl: authorizationUrl.toString(),
		transactionId
	};
};

export default startPasskeyWebAuthorization;
