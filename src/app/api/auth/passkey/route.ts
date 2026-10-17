import authCookieNames from '@assosync/contracts/auth/cookies';
import { cookies } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import Env from '@/config/env';
import startPasskeyWebAuthorization from '@/lib/auth/web-authorization';
import resolveWebSsoEndpoints from '@/lib/auth/web-sso-origin';

/** Starts Account-hosted discoverable-passkey authentication.
 * @returns Account authorization URL.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	const endpoints = resolveWebSsoEndpoints(request);

	if (!endpoints) {
		return NextResponse.json(
			{ error: 'authentication_failed' },
			{ status: 400 }
		);
	}

	try {
		const issued = await startPasskeyWebAuthorization(endpoints);
		const response = NextResponse.json({
			authorizationUrl: issued.authorizationUrl
		});

		const cookieStore = await cookies();

		cookieStore.set({
			name: authCookieNames.webAuthorization,
			value: issued.transactionId,
			httpOnly: true,
			secure: Env.public.environment !== 'development',
			sameSite: 'lax',
			path: '/',
			maxAge: 10 * 60
		});

		return response;
	} catch (error: unknown) {
		console.error(JSON.stringify({
			event: 'passkey_authentication_start_failure',
			errorName: error instanceof Error ? error.name : 'UnknownError'
		}));

		return NextResponse.json(
			{ error: 'authentication_failed' },
			{ status: 401 }
		);
	}
};
