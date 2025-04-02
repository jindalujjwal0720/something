'use client';
import { PropsWithChildren, useEffect } from 'react';
import { useSelector } from 'react-redux';
import { selectIsAuthenticated, selectRole } from '@/features/auth/stores/auth';
import { usePathname, useRouter } from 'next/navigation';
import { useAuth } from './auth-provider';
import Loading from '@/components/loading';

interface ProtectedComponentProps extends PropsWithChildren {
  roles?: string[];
}

const Protected = ({ roles, children }: ProtectedComponentProps) => {
  const isAuthenticated = useSelector(selectIsAuthenticated);
  const { isLoading } = useAuth();
  const role = useSelector(selectRole);
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (isLoading) return;
    if (!isAuthenticated) {
      router.push('/auth/login?from=' + pathname);
    } else if (roles && roles.length && (!role || !roles.includes(role))) {
      router.push('/');
    }
  }, [isAuthenticated, isLoading, pathname, role, roles, router]);

  if (isLoading) {
    return <Loading />;
  }

  return children;
};

export default Protected;
