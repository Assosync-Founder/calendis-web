import authCookieNames from '@assosync/contracts/auth/cookies';
import { cookies } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import Env from '@/config/env';
import startPasskeyWebAuthorization from '@/lib/auth/web-authorization';
import resolveWebSsoEndpoints from '@/lib/auth/web-sso-origin';

/** Starts a product-hosted discoverable-passkey authentication.
 * @param request - Same-origin browser request.
 * @returns Public WebAuthn options and an opaque ceremony identifier.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	const endpoints = resolveWebSsoEndpoints(request);

	if (!endpoints || request.headers.get('origin') !== endpoints.appOrigin) {
		return NextResponse.json({ error: 'authentication_failed' }, { status: 400 });
	}

	try {
		const issued = await startPasskeyWebAuthorization(endpoints);
		const response = NextResponse.json(
			{
				ceremonyId: issued.ceremonyId,
				options: issued.options
			},
			{ headers: { 'Cache-Control': 'no-store' } }
		);

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
		console.error(JSON.stringify({ event: 'passkey_authentication_start_failure', errorName: error instanceof Error ? error.name: 'UnknownError' }));

		return NextResponse.json({ error: 'authentication_failed' }, { status: 401 });
	}
};
