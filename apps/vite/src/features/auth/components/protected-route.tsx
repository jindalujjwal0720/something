import { useSelector } from 'react-redux';
import { Outlet, Navigate } from 'react-router-dom';
import { selectIsAuthenticated, selectRole } from '../stores/auth';
import { useAuth } from './auth-provider';

interface ProtectedRouteProps {
  roles?: string[];
}

const ProtectedRoute = ({ roles }: ProtectedRouteProps) => {
  const isAuthenticated = useSelector(selectIsAuthenticated);
  const role = useSelector(selectRole);
  const { isLoading } = useAuth();

  if (!isAuthenticated && isLoading)
    return (
      <div className="h-full w-full flex items-center justify-center">
        Loading...
      </div>
    );
  if (!isAuthenticated) return <Navigate to="/auth/login" />;

  if (roles && roles.length && (!role || !roles.includes(role)))
    return <Navigate to="/" />;

  return <Outlet />;
};

export default ProtectedRoute;
