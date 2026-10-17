import { defineProxyConfig } from '@assosync/proxy';
import cookies from '@assosync/contracts/auth/cookies';
import Env from '@/config/env';

const isDevelopment = Env.public.environment === 'development';
const isPreview = Env.public.environment === 'preview';
const previewHostname = 'preview.calendis.fr';

const resolveHostname = (
	developmentHostname: string,
	productionHostname: string
): string => {
	if (isDevelopment) {
		return developmentHostname;
	}

	if (isPreview) {
		return previewHostname;
	}

	return productionHostname;
};

const resolveUrl = (
	developmentUrl: string,
	previewUrl: string,
	productionUrl: string
): string => {
	if (isDevelopment) {
		return developmentUrl;
	}

	if (isPreview) {
		return previewUrl;
	}

	return productionUrl;
};

const appPublicRoutes = [
	isPreview ? '/app/login' : '/login',
	isPreview ? '/app/signup' : '/signup',
	isPreview ? '/app/auth/callback' : '/auth/callback'
] as const;

const proxyConfig = defineProxyConfig({
	scopes: {
		www: {
			hostname: resolveHostname(
				'www.localhost',
				'www.calendis.fr'
			),
			rewritePrefix: '/www'
		},

		app: {
			hostname: resolveHostname(
				'app.localhost',
				'app.calendis.fr'
			),
			rewritePrefix: '/app',
			authentication: {
				publicPaths: appPublicRoutes,
				loginUrl: resolveUrl(
					'http://app.localhost:3001/login',
					'https://preview.calendis.fr/app/login',
					'https://app.calendis.fr/login'
				)
			}
		}
	},

	forbiddenByScope: {
		www: [
			...appPublicRoutes,
			'/app'
		]
	},

	session: {
		cookieName: cookies.session,
		projectId: Env.public.firebase.projectId ?? ''
	},

	rateLimit: {
		enabled: !isDevelopment,
		key: 'calendis',
		url: Env.private.upstashRedis.restUrl ?? '',
		token: Env.private.upstashRedis.restToken ?? '',
		rules: [
			{
				name: 'auth',
				paths: [
					'/api/auth',
					'/api/login',
					'/api/signup'
				],
				requests: 20,
				window: '1 m'
			},

			{
				name: 'api',
				paths: ['/api'],
				requests: 100,
				window: '1 m'
			}
		]
	}
});

export default proxyConfig
