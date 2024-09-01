import { PropsWithChildren } from 'react';
import { useSelector } from 'react-redux';
import { selectIsAuthenticated, selectRole } from '@/features/auth/stores/auth';

interface ProtectedComponentProps extends PropsWithChildren {
  roles?: string[];
}

const ProtectedComponent = ({ roles, children }: ProtectedComponentProps) => {
  const isAuthenticated = useSelector(selectIsAuthenticated);
  const role = useSelector(selectRole);

  if (!isAuthenticated) return null;

  if (roles && roles.length && (!role || !roles.includes(role))) return null;

  return children;
};

export default ProtectedComponent;
