import { cookies, headers } from 'next/headers';
import { type NextRequest, NextResponse } from 'next/server';
import authCookieNames from '@assosync/contracts/auth/cookies';
import resolveWebSsoEndpoints from '@/lib/auth/web-sso-origin';

const isTrustedOrigin = async (appOrigin: string): Promise<boolean> => {
	const headerStore = await headers();

	return headerStore.get('origin') === appOrigin;
};

export const POST = async (request: NextRequest): Promise<Response> => {
	const endpoints = resolveWebSsoEndpoints(request);

	if (!endpoints || !(await isTrustedOrigin(endpoints.appOrigin))) {
		return NextResponse.json({ error: 'forbidden' }, { status: 403 });
	}

	const cookieStore = await cookies();
	const response = NextResponse.redirect(new URL(`${endpoints.appUrl}/login`), 303);

	cookieStore.delete(authCookieNames.session);
	cookieStore.delete(authCookieNames.connection);
	cookieStore.delete(authCookieNames.webAuthorization);

	return response;
};
