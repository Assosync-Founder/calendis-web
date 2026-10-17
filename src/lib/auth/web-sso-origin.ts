import 'server-only';

import Env from '@/config/env';
import type { WebSsoEndpoints } from '@/types/auth';

/** Resolves the public request origin from proxy-aware headers.
 * @param request - Incoming browser request.
 * @returns Valid public origin, or null when the proxy headers are invalid.
 */
const resolveRequestOrigin = (request: Request): string | null => {
	const requestUrl = new URL(request.url);
	const host = request.headers.get('x-forwarded-host')?.split(',')[0]?.trim() ??
		request.headers.get('host')?.trim() ??
		requestUrl.host;
	const forwardedProtocol = request.headers
		.get('x-forwarded-proto')
		?.split(',')[0]
		?.trim();
	const protocol = forwardedProtocol === 'http' || forwardedProtocol === 'https'
		? forwardedProtocol
		: requestUrl.protocol.slice(0, -1);

	try {
		return new URL(`${ protocol }://${ host }`).origin;
	} catch {
		return null;
	}
};

/** Resolves trusted SSO endpoints for the current Calendis origin.
 * @param request - Incoming Calendis browser request.
 * @returns Endpoints matching the exact supported product origin, or null.
 */
const resolveWebSsoEndpoints = (
	request: Request
): WebSsoEndpoints | null => {
	const appOrigin = resolveRequestOrigin(request);

	if (!appOrigin) {
		return null;
	}

	if (
		Env.public.environment === 'preview' &&
		appOrigin === 'https://preview.calendis.fr'
	) {
		return {
			accountUrl: 'https://preview.assosync.fr',
			appUrl: 'https://preview.calendis.fr/app',
			redirectUri: 'https://preview.calendis.fr/api/auth/callback',
			appOrigin
		};
	}

	if (Env.public.environment !== 'development') {
		const accountUrl = Env.private.webSso.authAccountUrl;
		const redirectUri = Env.private.webSso.authWebCalendisRedirectUri;

		if (
			!accountUrl ||
			!redirectUri ||
			new URL(redirectUri).origin !== appOrigin
		) {
			return null;
		}

		return {
			accountUrl,
			appUrl: appOrigin,
			redirectUri,
			appOrigin
		};
	}

	if (appOrigin === 'http://app.localhost:3001') {
		return {
			accountUrl: 'http://account.localhost:3000',
			appUrl: 'http://app.localhost:3001',
			redirectUri: 'http://app.localhost:3001/api/auth/callback',
			appOrigin
		};
	}

	return null;
};

export default resolveWebSsoEndpoints;
