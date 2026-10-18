import 'server-only';

import { createHash, randomBytes } from 'node:crypto';
import Env from '@/config/env';
import redis from '@/services/redis/redis.server';
import type { AccountPasskeyOptionsResponse, PasskeyAuthenticationTransaction, StartedPasskeyAuthorization, WebSsoEndpoints } from '@/types/auth';

const createSecret = (): string => {
	return randomBytes(32).toString('base64url');
};

const createHashValue = (value: string): string => {
	return createHash('sha256').update(value, 'utf8').digest('base64url');
};

const isRecord = (value: unknown): value is Record<string, unknown> => {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
};

const isAccountPasskeyOptionsResponse = (value: unknown): value is AccountPasskeyOptionsResponse => {
	if (!isRecord(value) || !isRecord(value.options)) {
		return false;
	}

	return typeof value.authorizationId === 'string' && typeof value.browserToken === 'string' && typeof value.challengeId === 'string' && typeof value.expiresAt === 'string' && typeof value.options.challenge === 'string';
};

/** Creates headers for an authenticated call to Assosync Account.
 * @returns Headers including the preview bypass when configured.
 */
const createAccountHeaders = (): HeadersInit => {
	const headers: HeadersInit = {
		'Content-Type': 'application/json'
	};

	if (Env.public.environment === 'preview' && Env.private.webSso.authAccountVercelBypassSecret) {
		headers['x-vercel-protection-bypass'] = Env.private.webSso.authAccountVercelBypassSecret;
	}

	return headers;
};

/** Starts a product-hosted discoverable-passkey transaction.
 * @param endpoints - Trusted Account and Calendis endpoints.
 * @returns Public browser options and local transaction identifier.
 */
const startPasskeyWebAuthorization = async (endpoints: WebSsoEndpoints): Promise<StartedPasskeyAuthorization> => {
	const clientSecret = Env.private.webSso.authWebClientSecret;

	if (!clientSecret) {
		throw new Error('The Calendis Web SSO configuration is incomplete.');
	}

	const transactionId = createSecret();
	const state = createSecret();
	const codeVerifier = createSecret();
	const codeChallenge = createHashValue(codeVerifier);
	const response = await fetch(`${endpoints.accountUrl}/api/auth/passkeys/web/options`, {
		method: 'POST',
		headers: createAccountHeaders(),
		cache: 'no-store',
		body: JSON.stringify({
			clientId: 'calendis',
			clientSecret,
			redirectUri: endpoints.redirectUri,
			passkeyOrigin: endpoints.appOrigin,
			state,
			codeChallenge
		})
	});
	const result: unknown = await response.json();

	if (!response.ok || !isAccountPasskeyOptionsResponse(result)) {
		throw new Error('Passkey authentication could not be started.');
	}

	const expiresAt = new Date(result.expiresAt);

	if (Number.isNaN(expiresAt.getTime())) {
		throw new Error('The passkey authorization expiration is invalid.');
	}

	const transaction: PasskeyAuthenticationTransaction = {
		state,
		codeVerifier,
		redirectUri: endpoints.redirectUri,
		returnTo: '/',
		authorizationId: result.authorizationId,
		browserToken: result.browserToken,
		challengeId: result.challengeId,
		passkeyOrigin: endpoints.appOrigin
	};
	const lifetimeMs = Math.min(10 * 60_000, expiresAt.getTime() - Date.now());

	if (lifetimeMs <= 0) {
		throw new Error('The passkey authorization is already expired.');
	}

	const stored = await redis.set(`auth:web:transactions:${createHashValue(transactionId)}`, JSON.stringify(transaction), { px: lifetimeMs, nx: true });

	if (stored !== 'OK') {
		throw new Error('The passkey transaction could not be persisted.');
	}

	return {
		transactionId,
		ceremonyId: transactionId,
		options: result.options
	};
};

export { createAccountHeaders, createHashValue };

export default startPasskeyWebAuthorization;
