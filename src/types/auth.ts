/** Temporary Web authentication transaction. */
export type WebAuthenticationTransaction = {
	/** CSRF correlation value. */
	readonly state: string;

	/** Secret PKCE verifier. */
	readonly codeVerifier: string;

	/** Exact callback URI registered with Assosync. */
	readonly redirectUri: string;

	/** Internal destination after successful authentication. */
	readonly returnTo: string;
};

/** Trusted endpoints used for one Calendis Web SSO flow. */
export type WebSsoEndpoints = {
	/** Account origin handling the central authentication flow. */
	readonly accountUrl: string;

	/** Public Calendis application URL, including its preview prefix. */
	readonly appUrl: string;

	/** Exact Calendis callback URI registered with Account. */
	readonly redirectUri: string;

	/** Current validated Calendis browser origin. */
	readonly appOrigin: string;
};

/** Response returned when Assosync creates an identity ticket. */
export type IdentityTicketResponse = {
	/** Opaque single-use identity ticket. */
	readonly identityTicket: string;

	/** ISO expiration time. */
	readonly expiresAt: string;
};

/** Session returned by the Assosync token exchange. */
export type WebSessionResponse = {
	/** Signed Firebase session cookie. */
	readonly firebaseSessionCookie: string;

	/** Revocable application session token. */
	readonly sessionToken: string;

	/** ISO session expiration time. */
	readonly expiresAt: string;
};
