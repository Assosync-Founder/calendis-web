import 'server-only';

import Env from '@/config/env';
import { createAccountHeaders } from '@/lib/auth/web-authorization';
import type { PasskeyAuthenticationTransaction, WebSsoEndpoints } from '@/types/auth';

const MAXIMUM_BODY_LENGTH = 64 * 1_024;

/** Reads a bounded same-origin JSON request.
 * @param request - Incoming browser request.
 * @param endpoints - Trusted endpoints resolved for the current host.
 * @returns Parsed record or null when the boundary validation fails.
 */
const readPasskeyBrowserRequest = async (request: Request, endpoints: WebSsoEndpoints): Promise<Record<string, unknown> | null> => {
	if (request.headers.get('origin') !== endpoints.appOrigin || !request.headers.get('content-type')?.toLowerCase().includes('application/json')) {
		return null;
	}

	const rawBody = await request.text();

	if (!rawBody || rawBody.length > MAXIMUM_BODY_LENGTH) {
		return null;
	}

	let value: unknown;

	try {
		value = JSON.parse(rawBody);
	} catch {
		return null;
	}

	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		return null;
	}

	return Object.fromEntries(Object.entries(value));
};

/** Creates the confidential fields shared by Account passkey calls.
 * @param transaction - Server-held passkey transaction.
 * @param endpoints - Trusted endpoints for the current Calendis host.
 * @returns Confidential upstream request fields.
 * @throws {Error} When the server secret is missing.
 */
const createPasskeyUpstreamContext = (transaction: PasskeyAuthenticationTransaction, endpoints: WebSsoEndpoints) => {
	const clientSecret = Env.private.webSso.authWebClientSecret;

	if (!clientSecret) {
		throw new Error('The Calendis Web SSO configuration is incomplete.');
	}

	return {
		clientId: 'calendis',
		clientSecret,
		redirectUri: endpoints.redirectUri,
		passkeyOrigin: endpoints.appOrigin,
		authorizationId: transaction.authorizationId,
		browserToken: transaction.browserToken
	};
};

/** Calls one authenticated Account passkey endpoint.
 * @param endpoints - Trusted Account endpoints.
 * @param pathname - Fixed Account API pathname.
 * @param body - Serialized confidential request body.
 * @returns Account response.
 */
const fetchAccountPasskey = async (endpoints: WebSsoEndpoints, pathname: string, body: Record<string, unknown>): Promise<Response> => {
	return fetch(`${endpoints.accountUrl}${pathname}`, {
		method: 'POST',
		headers: createAccountHeaders(),
		cache: 'no-store',
		body: JSON.stringify(body)
	});
};

export { createPasskeyUpstreamContext, fetchAccountPasskey, readPasskeyBrowserRequest };
