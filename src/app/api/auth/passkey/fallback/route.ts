import authCookieNames from '@assosync/contracts/auth/cookies';
import { cookies } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import { createPasskeyUpstreamContext, fetchAccountPasskey, readPasskeyBrowserRequest } from '@/lib/auth/passkey-http';
import resolvePasskeyTransaction from '@/lib/auth/passkey-transaction';
import resolveWebSsoEndpoints from '@/lib/auth/web-sso-origin';

/** Falls back to the Account-hosted ceremony for incompatible browsers.
 * @param request - Same-origin browser fallback request.
 * @returns Trusted Account continuation URL.
 */
export const POST = async (request: NextRequest): Promise<Response> => {
	const endpoints = resolveWebSsoEndpoints(request);

	if (!endpoints) {
		return NextResponse.json({ error: 'authentication_failed' }, { status: 400 });
	}

	const body = await readPasskeyBrowserRequest(request, endpoints);
	const cookieStore = await cookies();
	const transactionId = cookieStore.get(authCookieNames.webAuthorization)?.value;

	if (!body || !transactionId || body.ceremonyId !== transactionId) {
		return NextResponse.json({ error: 'request_invalid' }, { status: 400 });
	}

	try {
		const transaction = await resolvePasskeyTransaction(transactionId);

		if (!transaction || transaction.redirectUri !== endpoints.redirectUri || transaction.passkeyOrigin !== endpoints.appOrigin) {
			return NextResponse.json({ error: 'authentication_failed' }, { status: 401 });
		}

		const upstreamResponse = await fetchAccountPasskey(
			endpoints,
			'/api/auth/passkeys/web/fallback',
			createPasskeyUpstreamContext(transaction, endpoints)
		);
		const result: unknown = await upstreamResponse.json();

		if (!upstreamResponse.ok || typeof result !== 'object' || result === null || !('continuationUrl' in result) || typeof result.continuationUrl !== 'string') {
			return NextResponse.json({ error: 'authentication_failed' }, { status: 401 });
		}

		const continuationUrl = new URL(result.continuationUrl);

		if (continuationUrl.origin !== endpoints.accountUrl) {
			return NextResponse.json({ error: 'authentication_failed' }, { status: 502 });
		}

		return NextResponse.json({ continuationUrl: continuationUrl.toString() }, { headers: { 'Cache-Control': 'no-store' } });
	} catch (error: unknown) {
		console.error(JSON.stringify({ event: 'passkey_fallback_failure', errorName: error instanceof Error ? error.name : 'UnknownError' }));

		return NextResponse.json({ error: 'authentication_failed' }, { status: 401 });
	}
};
