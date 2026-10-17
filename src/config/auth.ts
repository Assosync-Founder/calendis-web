/** Product authentication configuration shared by server and client modules. */
const authConfig = {
	cookieNames: {
		flash: 'c_flh'
	},
	flashCodes: {
		passkeyAuthenticationFailed: 'passkey_authentication_failed',
		emailCodeRateLimited15Minutes: 'email_code_rate_limited_15_minutes',
		emailCodeRateLimited1Hour: 'email_code_rate_limited_1_hour',
		emailCodeRateLimited6Hours: 'email_code_rate_limited_6_hours',
		emailCodeRateLimited24Hours: 'email_code_rate_limited_24_hours',
		authenticationFailed: 'authentication_failed',
	},
	flashLifetimeSeconds: 60
} as const;

export default authConfig;
