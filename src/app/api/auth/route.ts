import { createHash, randomBytes } from 'node:crypto';
import authCookieNames from '@assosync/contracts/auth/cookies';
import { cookies } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import Env from '@/config/env';
import resolveWebSsoEndpoints from '@/lib/auth/web-sso-origin';
import redis from '@/services/redis/redis.server';
import type {
	IdentityTicketResponse,
	WebAuthenticationTransaction
} from '@/types/auth';

const createSecret = (): string => {
	return randomBytes(32).toString('base64url');
};

const createHashValue = (
	value: string
): string => {
	return createHash('sha256')
		.update(value, 'utf8')
		.digest('base64url');
};

/** Reads a stable public error code from an upstream response payload.
 * @param value - Unknown upstream response payload.
 * @returns Public error code when one is available.
 */
const readUpstreamErrorCode = (
	value: unknown
): string | null => {
	if (
		typeof value !== 'object' ||
		value === null ||
		!('error' in value) ||
		typeof value.error !== 'string'
	) {
		return null;
	}

	return value.error;
};

export const POST = async (
	request: NextRequest
): Promise<Response> => {
	const endpoints = resolveWebSsoEndpoints(request);

	if (!endpoints) {
		return NextResponse.json(
			{ error: 'authentication_failed' },
			{ status: 400 }
		);
	}

	const body: unknown = await request.json();

	if (
		typeof body !== 'object' ||
		body === null ||
		!('idToken' in body) ||
		typeof body.idToken !== 'string'
	) {
		return NextResponse.json(
			{ error: 'request_invalid' },
			{ status: 400 }
		);
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
		`auth:web:transactions:${ createHashValue(transactionId) }`,
		JSON.stringify(transaction),
		{
			px: 10 * 60_000,
			nx: true
		}
	);

	const headers: HeadersInit = {
		'Content-Type': 'application/json'
	};

	if (Env.public.environment === 'preview' && Env.private.webSso.authAccountVercelBypassSecret) {
		headers['x-vercel-protection-bypass'] = Env.private.webSso.authAccountVercelBypassSecret;
	}

	const identityResponse = await fetch(
		`${ endpoints.accountUrl }/api/auth/web/identity`,
		{
			method: 'POST',
			headers,
			cache: 'no-store',
			body: JSON.stringify({
				clientId: 'calendis',
				clientSecret: Env.private.webSso.authWebClientSecret,
				redirectUri: endpoints.redirectUri,
				idToken: body.idToken,
				state,
				codeChallenge
			})
		}
	);
	const identityResult: unknown = await identityResponse.json();

	if (!identityResponse.ok) {
		console.error(JSON.stringify({
			event: 'web_identity_upstream_failure',
			upstreamStatus: identityResponse.status,
			upstreamError: readUpstreamErrorCode(identityResult),
			upstreamRequestId:
				identityResponse.headers.get('x-request-id')
		}));

		return NextResponse.json(
			{ error: 'authentication_failed' },
			{ status: 401 }
		);
	}

	if (
		typeof identityResult !== 'object' ||
		identityResult === null ||
		!('identityTicket' in identityResult) ||
		typeof identityResult.identityTicket !== 'string'
	) {
		return NextResponse.json(
			{ error: 'authentication_failed' },
			{ status: 502 }
		);
	}

	const identityTicketResponse =
		identityResult as IdentityTicketResponse;

	const authorizationUrl = new URL(
		'/api/auth/web/authorize',
		endpoints.accountUrl
	);

	authorizationUrl.searchParams.set(
		'identity_ticket',
		identityTicketResponse.identityTicket
	);

	const response = NextResponse.json({
		authorizationUrl: authorizationUrl.toString()
	});

	const cookieStore = await cookies();

	cookieStore.set({
		name: authCookieNames.webAuthorization,
		value: transactionId,
		httpOnly: true,
		secure: Env.public.environment !== 'development',
		sameSite: 'lax',
		path: '/',
		maxAge: 10 * 60
	});

	return response;
};
