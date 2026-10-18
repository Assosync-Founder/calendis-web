import { createHash } from 'node:crypto';
import { type NextRequest, NextResponse } from 'next/server';
import authConfig from '@/config/auth';
import createAuthenticationFailureResponse from '@/lib/auth/auth-failure';
import { redirectToLogin } from '@/lib/auth/auth-navigation';
import resolveWebSsoEndpoints from '@/lib/auth/web-sso-origin';
import redis from '@/services/redis/redis.server';

const APPLICATION_ID = 'calendis';
const FLASH_TICKET_PATTERN = /^[A-Za-z0-9_-]{43}$/u;

/** Hashes an opaque Account-issued flash ticket. */
const createTicketHash = (ticket: string): string => {
	return createHash('sha256')
		.update(ticket, 'utf8')
		.digest('base64url');
};

/** Checks whether a value is a plain record. */
const isRecord = (value: unknown): value is Record<string, unknown> => {
	return typeof value === 'object' && value !== null;
};

/** Checks whether a code can safely be stored in the product flash cookie. */
const isSupportedFlashCode = (value: string): boolean => {
	return (
		value === authConfig.flashCodes.passkeyAuthenticationCancelled ||
		value === authConfig.flashCodes.passkeyAuthenticationFailed ||
		value === authConfig.flashCodes.emailCodeRateLimited15Minutes ||
		value === authConfig.flashCodes.emailCodeRateLimited1Hour ||
		value === authConfig.flashCodes.emailCodeRateLimited6Hours ||
		value === authConfig.flashCodes.emailCodeRateLimited24Hours ||
		value === authConfig.flashCodes.authenticationFailed
	);
};

/** Atomically consumes an Account-issued product flash ticket. */
const consumeFlashTicket = async (ticket: string): Promise<string | null> => {
	if (!FLASH_TICKET_PATTERN.test(ticket)) {
		return null;
	}

	const value = await redis.getdel<unknown>(`auth:web:flash:${createTicketHash(ticket)}`);

	if (!isRecord(value) || value.applicationId !== APPLICATION_ID || typeof value.flashCode !== 'string' || !isSupportedFlashCode(value.flashCode)) {
		return null;
	}

	return value.flashCode;
};

/** Consumes an Account flash relay and returns the browser to product login.
 * @param request - Browser request redirected by Assosync Account.
 * @param context - Dynamic route context containing the opaque ticket.
 * @returns Product login redirect, optionally containing a flash cookie.
 */
export const GET = async (request: NextRequest, context: RouteContext<'/api/auth/flash/[ticket]'>): Promise<Response> => {
	const parameters = await context.params;
	const endpoints = resolveWebSsoEndpoints(request);

	if (!endpoints) {
		return NextResponse.json({ error: 'authentication_failed' }, { status: 400 });
	}

	try {
		const flashCode = await consumeFlashTicket(parameters.ticket);

		if (!flashCode) {
			return redirectToLogin(endpoints.appUrl);
		}

		return createAuthenticationFailureResponse(flashCode, endpoints);
	} catch (error: unknown) {
		console.error(JSON.stringify({
			event: 'authentication_flash_ticket_consumption_failure',
			errorName: error instanceof Error ? error.name: 'UnknownError'
		}));

		return redirectToLogin(endpoints.appUrl);
	}
};
