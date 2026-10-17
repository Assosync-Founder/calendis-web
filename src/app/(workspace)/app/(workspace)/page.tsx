import React from 'react';

const DashboardPage = () => {
	return (
		<form action="/api/auth/logout" method="post">
			<button type="submit">Déconnexion</button>
		</form>
	);
};

export default DashboardPage;