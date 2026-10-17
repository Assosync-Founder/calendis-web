/**
 * Provides the application's public and server-side environment variables.
 *
 * Private values must only be accessed from server-side modules.
 */
const Env = {
	public: {
		environment: process.env.NEXT_PUBLIC_ENVIRONMENT,
		serverUrl: process.env.NEXT_PUBLIC_SERVER_URL,
		firebase: {
			apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
			authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
			projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
			storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET,
			messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
			appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID,
			functionUrl: process.env.NEXT_PUBLIC_FIREBASE_FUNCTION_URL
		},
		stripe: {
			publishableKey: process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY
		},
		mapTiler: {
			key: process.env.NEXT_PUBLIC_MAPTILER_KEY
		},
		supabase: {
			url: process.env.NEXT_PUBLIC_SUPABASE_URL,
			anonKey: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
		},
		facebook: {
			appId: process.env.NEXT_PUBLIC_FACEBOOK_APP_ID
		}
	},
	private: {
		firebase: {
			projectId: process.env.FIREBASE_PROJECT_ID,
			clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
			privateKey: process.env.FIREBASE_PRIVATE_KEY
		},
		stripe: {
			secretKey: process.env.STRIPE_SECRET_KEY,
		},
		supabase: {
			serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY
		},
		facebook: {
			appSecret: process.env.FACEBOOK_APP_SECRET
		},
		authEmail: {
			challengeSecret: process.env.AUTH_EMAIL_CHALLENGE_SECRET,
			noReplyFrom: process.env.EMAIL_NOREPLY_FROM,
			from: process.env.EMAIL_FROM
		},
		webSso: {
			authAccountUrl: process.env.AUTH_ACCOUNT_URL,
			authWebClientSecret: process.env.AUTH_WEB_CLIENT_SECRET,
			authWebCalendisRedirectUri: process.env.AUTH_WEB_CALENDIS_REDIRECT_URI
		},
		upstashRedis: {
			restUrl: process.env.UPSTASH_REDIS_REST_URL,
			restToken: process.env.UPSTASH_REDIS_REST_TOKEN
		}
	}
} as const;

export default Env;
