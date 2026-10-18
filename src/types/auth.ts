import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/browser';

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

/** Server-held transaction for a product-hosted passkey ceremony. */
export type PasskeyAuthenticationTransaction = WebAuthenticationTransaction & {
	/** Account authorization identifier. */
	readonly authorizationId: string;

	/** Secret that binds server-to-server passkey requests. */
	readonly browserToken: string;

	/** One-time WebAuthn challenge identifier. */
	readonly challengeId: string;

	/** Exact Calendis origin performing the ceremony. */
	readonly passkeyOrigin: string;
};

/** Public passkey options returned to the Calendis browser. */
export type PasskeyOptionsResponse = {
	/** Opaque local ceremony identifier. */
	readonly ceremonyId: string;

	/** Browser-compatible WebAuthn request options. */
	readonly options: PublicKeyCredentialRequestOptionsJSON;
};

/** Product-hosted passkey options paired with the server transaction identifier. */
export type StartedPasskeyAuthorization = PasskeyOptionsResponse & {
	/** Raw local transaction identifier stored in an HTTP-only cookie. */
	readonly transactionId: string;
};

/** Confidential response returned by the Account passkey options endpoint. */
export type AccountPasskeyOptionsResponse = {
	/** Account authorization identifier retained by the Calendis server. */
	readonly authorizationId: string;

	/** Server-only authorization binding secret. */
	readonly browserToken: string;

	/** One-time WebAuthn challenge identifier. */
	readonly challengeId: string;

	/** Public WebAuthn request options. */
	readonly options: PublicKeyCredentialRequestOptionsJSON;

	/** ISO expiration time for the Account authorization. */
	readonly expiresAt: string;
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
