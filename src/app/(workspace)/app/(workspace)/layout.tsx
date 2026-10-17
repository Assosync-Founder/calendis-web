import React from 'react';
import type { ChildrenType } from '@/types/app';

const WorkspaceLayout = ({ children }: ChildrenType) => {
	return (
		<>
			{ children }
		</>
	);
};

export default WorkspaceLayout;