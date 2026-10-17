import { cookies, headers } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import { isDocumentRequest, redirectToLogin } from '@/lib/auth/auth-navigation';
import resolveWebSsoEndpoints from '@/lib/auth/web-sso-origin';

/** Consumes the current product authentication flash message.
 * @returns Flash code, or null when no supported message is present.
 */
export const GET = async (
	request: NextRequest
): Promise<Response> => {
	const [cookieStore, headerStore] = await Promise.all([
		cookies(),
		headers()
	]);

	if (isDocumentRequest(headerStore)) {
		const endpoints = resolveWebSsoEndpoints(request);

		if (!endpoints) {
			return NextResponse.json(
				{ error: 'authentication_failed' },
				{ status: 400 }
			);
		}

		return redirectToLogin(endpoints.appUrl);
	}

	const storedCode = cookieStore.get(
		authConfig.cookieNames.flash
	)?.value;
	const code =
		storedCode === authConfig.flashCodes.passkeyAuthenticationFailed ||
		storedCode ===
		authConfig.flashCodes.emailCodeRateLimited15Minutes ||
		storedCode ===
		authConfig.flashCodes.emailCodeRateLimited1Hour ||
		storedCode ===
		authConfig.flashCodes.emailCodeRateLimited6Hours ||
		storedCode ===
		authConfig.flashCodes.emailCodeRateLimited24Hours ||
		storedCode === authConfig.flashCodes.authenticationFailed
			? storedCode
			: null;
	const response = NextResponse.json(
		{ code },
		{ headers: { 'Cache-Control': 'no-store' } }
	);

	cookieStore.delete(authConfig.cookieNames.flash);

	return response;
};
