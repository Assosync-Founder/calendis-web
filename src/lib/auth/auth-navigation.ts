import 'server-only';

import { NextResponse } from 'next/server';

/** Determines whether an incoming request is a document navigation.
 * @param requestHeaders - Incoming request headers.
 * @returns Whether the request expects an HTML document.
 */
export const isDocumentRequest = (requestHeaders: Headers): boolean => {
	const destination = requestHeaders.get('Sec-Fetch-Dest');

	const accept = requestHeaders.get('Accept') ?? '';

	return (
		destination === 'document' ||
		accept.includes('text/html')
	);
};

/** Redirects the browser to the product login page.
 * @param appUrl - Validated public product application URL.
 * @returns Product login redirect response.
 */
export const redirectToLogin = (appUrl: string): Response => {
	return NextResponse.redirect(new URL(`${appUrl}/login`), 303);
};
