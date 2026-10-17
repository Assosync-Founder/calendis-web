import { createHash } from 'node:crypto';
import authCookieNames from '@assosync/contracts/auth/cookies';
import { cookies } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import Env from '@/config/env';
import createAuthenticationFailureResponse from '@/lib/auth/auth-failure';
import resolveWebSsoEndpoints from '@/lib/auth/web-sso-origin';
import redis from '@/services/redis/redis.server';
import type {
	WebAuthenticationTransaction,
	WebSessionResponse
} from '@/types/auth';

/** Creates a SHA-256 digest suitable for a Redis key. */
const createHashValue = (value: string): string => {
	return createHash('sha256')
		.update(value, 'utf8')
		.digest('base64url');
};

/** Checks whether a value is a plain record. */
const isRecord = (
	value: unknown
): value is Record<string, unknown> => {
	return typeof value === 'object' && value !== null;
};

/** Validates a temporary product SSO transaction read from Redis. */
const isWebAuthenticationTransaction = (
	value: unknown
): value is WebAuthenticationTransaction => {
	if (!isRecord(value)) {
		return false;
	}

	return (
		typeof value.state === 'string' &&
		typeof value.codeVerifier === 'string' &&
		typeof value.redirectUri === 'string' &&
		typeof value.returnTo === 'string'
	);
};

/** Validates the session returned by Assosync Account. */
const isWebSessionResponse = (
	value: unknown
): value is WebSessionResponse => {
	if (!isRecord(value)) {
		return false;
	}

	return (
		typeof value.firebaseSessionCookie === 'string' &&
		typeof value.sessionToken === 'string' &&
		typeof value.expiresAt === 'string'
	);
};

/** Creates an internal Calendis URL from a safe relative pathname. */
const createAppUrl = (
	appUrl: string,
	pathname: string
): URL | null => {
	if (!pathname.startsWith('/') || pathname.startsWith('//')) {
		return null;
	}

	const normalizedAppUrl = appUrl.endsWith('/')
		? appUrl
		: `${appUrl}/`;

	return new URL(pathname.slice(1), normalizedAppUrl);
};

/** Exchanges an Assosync authorization for a local Calendis session. */
export const GET = async (
	request: NextRequest
): Promise<Response> => {
	const endpoints = resolveWebSsoEndpoints(request);

	if (!endpoints) {
		return NextResponse.json(
			{ error: 'authentication_failed' },
			{ status: 400 }
		);
	}

	const failureResponse = (): Promise<Response> => {
		return createAuthenticationFailureResponse(
			authConfig.flashCodes.authenticationFailed,
			endpoints
		);
	};
	const cookieStore = await cookies();
	const transactionId = cookieStore.get(
		authCookieNames.webAuthorization
	)?.value;

	if (!transactionId) {
		return failureResponse();
	}

	try {
		const transactionValue = await redis.getdel<unknown>(
			`auth:web:transactions:${createHashValue(transactionId)}`
		);

		if (!isWebAuthenticationTransaction(transactionValue)) {
			return failureResponse();
		}

		if (transactionValue.redirectUri !== endpoints.redirectUri) {
			return failureResponse();
		}

		const tokenResponse = await fetch(
			`${endpoints.accountUrl}/api/auth/web/token`,
			{
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				cache: 'no-store',
				body: JSON.stringify({
					clientId: 'calendis',
					clientSecret:
					Env.private.webSso.authWebClientSecret,
					codeVerifier: transactionValue.codeVerifier,
					state: transactionValue.state,
					redirectUri: transactionValue.redirectUri
				})
			}
		);

		if (!tokenResponse.ok) {
			return failureResponse();
		}

		const sessionValue: unknown = await tokenResponse.json();

		if (!isWebSessionResponse(sessionValue)) {
			return failureResponse();
		}

		const expires = new Date(sessionValue.expiresAt);

		if (Number.isNaN(expires.getTime())) {
			return failureResponse();
		}

		const destination = createAppUrl(
			endpoints.appUrl,
			transactionValue.returnTo
		);

		if (!destination) {
			return failureResponse();
		}

		const response = NextResponse.redirect(destination);

		cookieStore.set({
			name: authCookieNames.session,
			value: sessionValue.firebaseSessionCookie,
			httpOnly: true,
			secure: Env.public.environment !== 'development',
			sameSite: 'lax',
			path: '/',
			expires
		});

		cookieStore.set({
			name: authCookieNames.connection,
			value: sessionValue.sessionToken,
			httpOnly: true,
			secure: Env.public.environment !== 'development',
			sameSite: 'lax',
			path: '/',
			expires
		});

		cookieStore.delete(
			authCookieNames.webAuthorization
		);

		return response;
	} catch (error: unknown) {
		console.error(JSON.stringify({
			event: 'authentication_callback_failure',
			errorName: error instanceof Error
				? error.name
				: 'UnknownError'
		}));

		return failureResponse();
	}
};
