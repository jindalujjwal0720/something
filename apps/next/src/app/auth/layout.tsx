'use client';
import { useSelector } from 'react-redux';
import { selectIsAuthenticated } from '@/features/auth/stores/auth';
import { PropsWithChildren } from 'react';
import { redirect, useSearchParams } from 'next/navigation';

const AuthLayout = ({ children }: PropsWithChildren) => {
  const isAuthenticated = useSelector(selectIsAuthenticated);
  const from = useSearchParams().get('from') || '/';

  if (isAuthenticated) {
    redirect(from);
  }

  return (
    <div className="flex items-center justify-center h-screen">{children}</div>
  );
};

export default AuthLayout;
