import React from 'react';
import type { ChildrenType } from '@/types/app';

const AuthLayout = ({ children }: ChildrenType) => {
	return (
		<>
			{ children }
		</>
	);
};

export default AuthLayout;