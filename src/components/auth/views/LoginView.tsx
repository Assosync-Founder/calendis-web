'use client';

import React, { useEffect, useState } from 'react';
import {
	inMemoryPersistence,
	setPersistence,
	signInWithEmailAndPassword
} from 'firebase/auth';
import authConfig from '@/config/auth';
import firebaseClient from '@/services/firebase/firebase-client';

const isRecord = (value: unknown): value is Record<string, unknown> => {
	return typeof value === 'object' && value !== null;
};

const LoginView = () => {
	const [error, setError] = useState<string | null>(null);
	const [pending, setPending] = useState(false);
	const [email, setEmail] = useState('');

	useEffect(() => {
		const consumeFlashMessage = async (): Promise<void> => {
			try {
				const response = await fetch('/api/auth/flash', {
					cache: 'no-store'
				});
				const result: unknown = await response.json();

				if (!response.ok || !isRecord(result)) {
					return;
				}

				if (
					result.code ===
					authConfig.flashCodes.passkeyAuthenticationFailed
				) {
					setError(
						'Impossible de vous connecter avec cette clé d’accès.'
					);

					return;
				}

				if (
					result.code ===
					authConfig.flashCodes.emailCodeRateLimited15Minutes
				) {
					setError(
						'Trop de codes de vérification ont été demandés par e-mail. Réessayez dans 15 minutes.'
					);

					return;
				}

				if (
					result.code ===
					authConfig.flashCodes.emailCodeRateLimited1Hour
				) {
					setError(
						'Trop de codes de vérification ont été demandés par e-mail. Réessayez dans 1 heure.'
					);

					return;
				}

				if (
					result.code ===
					authConfig.flashCodes.emailCodeRateLimited6Hours
				) {
					setError(
						'Trop de codes de vérification ont été demandés par e-mail. Réessayez dans 6 heures.'
					);

					return;
				}

				if (
					result.code ===
					authConfig.flashCodes.emailCodeRateLimited24Hours
				) {
					setError(
						'Trop de codes de vérification ont été demandés par e-mail. Réessayez dans 24 heures.'
					);

					return;
				}

				if (
					result.code ===
					authConfig.flashCodes.authenticationFailed
				) {
					setError(
						'La connexion n’a pas pu être finalisée. Veuillez réessayer.'
					);
				}
			} catch (error: unknown) {
				console.error(JSON.stringify({
					event: 'authentication_flash_consumption_failure',
					errorName: error instanceof Error
						? error.name
						: 'UnknownError'
				}));
			}
		};

		void consumeFlashMessage();
	}, []);

	const handleSubmit = async (
		event: React.FormEvent<HTMLFormElement>
	): Promise<void> => {
		event.preventDefault();

		setPending(true);
		setError(null);

		const formData = new FormData(event.currentTarget);
		const submittedEmail = formData.get('email');
		const password = formData.get('password');

		if (
			typeof submittedEmail !== 'string' ||
			typeof password !== 'string'
		) {
			setError('Le formulaire est invalide.');
			setPending(false);

			return;
		}

		try {
			await setPersistence(firebaseClient.auth, inMemoryPersistence);

			const credential = await signInWithEmailAndPassword(
				firebaseClient.auth,
				submittedEmail,
				password
			);
			const idToken = await credential.user.getIdToken(true);

			const response = await fetch(
				'/api/auth',
				{
					method: 'POST',
					headers: {
						'Content-Type': 'application/json'
					},
					body: JSON.stringify({ idToken })
				}
			);

			const result: unknown = await response.json();

			if (
				!response.ok ||
				typeof result !== 'object' ||
				result === null ||
				!('authorizationUrl' in result) ||
				typeof result.authorizationUrl !== 'string'
			) {
				setError(
					'Impossible de démarrer la connexion.'
				);
				setPending(false);

				return;
			}

			window.location.assign(result.authorizationUrl);
		} catch {
			setError(
				'Adresse email ou mot de passe incorrect.'
			);
			setPending(false);
		}
	};

	const handlePasskey = async (): Promise<void> => {
		setPending(true);
		setError(null);

		try {
			const response = await fetch('/api/auth/passkey', {
				method: 'POST'
			});
			const result: unknown = await response.json();

			if (
				!response.ok ||
				typeof result !== 'object' ||
				result === null ||
				!('authorizationUrl' in result) ||
				typeof result.authorizationUrl !== 'string'
			) {
				setError(
					'Aucune passkey utilisable n’a été trouvée pour ce compte.'
				);
				setPending(false);

				return;
			}

			window.location.assign(result.authorizationUrl);
		} catch (caught: unknown) {
			setError('Aucune passkey utilisable n’a été trouvée pour ce compte.');
			setPending(false);
		}
	};

	return (
		<div className="flex items-center justify-center max-w-lg mx-auto h-dvh">
			<form onSubmit={handleSubmit} className="flex flex-col w-full space-y-4">
				<div className="w-full">
					<label htmlFor="email">
						Adresse email
					</label>

					<input
						id="email"
						name="email"
						type="email"
						value={email}
						onChange={(event) => {
							setEmail(event.currentTarget.value);
						}}
						autoComplete="email"
						className="bg-white border border-slate-300 w-full py-2 px-3"
						required
					/>
				</div>

				<div className="w-full">
					<label htmlFor="password">
						Mot de passe
					</label>

					<input
						id="password"
						name="password"
						type="password"
						className="bg-white border border-slate-300 w-full py-2 px-3"
						autoComplete="current-password"
						required
					/>
				</div>

				{error ? <p role="alert">{error}</p> : null}

				<button type="submit" disabled={pending}>
					{pending
						? 'Connexion en cours…'
						: 'Se connecter'}
				</button>

				<button
					type="button"
					disabled={pending}
					onClick={() => {
						void handlePasskey();
					}}
				>
					Se connecter avec Touch ID ou Windows Hello
				</button>
			</form>
		</div>
	);
};

export default LoginView;
