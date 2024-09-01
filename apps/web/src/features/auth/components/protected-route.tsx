import { useSelector } from 'react-redux';
import { Outlet, Navigate } from 'react-router-dom';
import { selectIsAuthenticated, selectRole } from '../stores/auth';

interface ProtectedRouteProps {
  roles?: string[];
}

const ProtectedRoute = ({ roles }: ProtectedRouteProps) => {
  const isAuthenticated = useSelector(selectIsAuthenticated);
  const role = useSelector(selectRole);

  if (!isAuthenticated) return <Navigate to="/auth/login" />;

  if (roles && roles.length && (!role || !roles.includes(role)))
    return <Navigate to="/" />;

  return <Outlet />;
};

export default ProtectedRoute;
