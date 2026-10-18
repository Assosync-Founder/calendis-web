import 'server-only';

import { createHashValue } from '@/lib/auth/web-authorization';
import redis from '@/services/redis/redis.server';
import type { PasskeyAuthenticationTransaction } from '@/types/auth';

const isRecord = (value: unknown): value is Record<string, unknown> => {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
};

/** Validates a server-held passkey transaction.
 * @param value - Unknown Redis value.
 * @returns Whether the value is a complete transaction.
 */
const isPasskeyAuthenticationTransaction = (value: unknown): value is PasskeyAuthenticationTransaction => {
	if (!isRecord(value)) {
		return false;
	}

	return typeof value.state === 'string' && typeof value.codeVerifier === 'string' && typeof value.redirectUri === 'string' && typeof value.returnTo === 'string' && typeof value.authorizationId === 'string' && typeof value.browserToken === 'string' && typeof value.challengeId === 'string' && typeof value.passkeyOrigin === 'string';
};

/** Loads an active passkey transaction without consuming callback state.
 * @param transactionId - Raw transaction cookie value.
 * @returns Active transaction or null.
 */
const resolvePasskeyTransaction = async (transactionId: string): Promise<PasskeyAuthenticationTransaction | null> => {
	const value = await redis.get<unknown>(`auth:web:transactions:${createHashValue(transactionId)}`);

	return isPasskeyAuthenticationTransaction(value) ? value : null;
};

export default resolvePasskeyTransaction;
