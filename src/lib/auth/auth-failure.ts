import { createHash } from 'node:crypto';
import authCookieNames from '@assosync/contracts/auth/cookies';
import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import Env from '@/config/env';
import redis from '@/services/redis/redis.server';
import type { WebSsoEndpoints } from '@/types/auth';

/** Hashes a browser transaction identifier before Redis lookup.
 * @param value - Raw browser transaction identifier.
 * @returns Base64url-encoded SHA-256 digest.
 */
const createHashValue = (value: string): string => {
	return createHash('sha256')
		.update(value, 'utf8')
		.digest('base64url');
};

/** Stores a short-lived product authentication failure before returning to login.
 * @param flashCode - Allowlisted product flash code.
 * @param endpoints - Validated endpoints for the current product origin.
 * @returns Redirect response without error query parameters.
 */
const createAuthenticationFailureResponse = async (flashCode: string, endpoints: WebSsoEndpoints): Promise<Response> => {
	const cookieStore = await cookies();
	const transactionId = cookieStore.get(authCookieNames.webAuthorization)?.value;

	if (transactionId) {
		try {
			await redis.del(`auth:web:transactions:${createHashValue(transactionId)}`);
		} catch (error: unknown) {
			console.error(JSON.stringify({
				event: 'authentication_transaction_cleanup_failure',
				errorName: error instanceof Error ? error.name: 'UnknownError'
			}));
		}
	}

	const response = NextResponse.redirect(new URL(`${endpoints.appUrl}/login`));

	cookieStore.set({
		name: authConfig.cookieNames.flash,
		value: flashCode,
		httpOnly: true,
		secure: Env.public.environment !== 'development',
		sameSite: 'lax',
		path: '/',
		maxAge: authConfig.flashLifetimeSeconds
	});

	cookieStore.delete(authCookieNames.webAuthorization);

	return response;
};

export default createAuthenticationFailureResponse;
