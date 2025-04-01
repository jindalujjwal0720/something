'use client';
import { createContext, PropsWithChildren, useContext, useMemo } from 'react';
import { useGetMeQuery } from '../api/auth';
import { IUser } from '@/types/models/user';
import { SanitisedAccount } from '@/types/models/account';

interface AuthContextValue {
  user: IUser | undefined;
  account: SanitisedAccount | undefined;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider = ({ children }: PropsWithChildren) => {
  const { data: { user, account } = {}, isLoading } = useGetMeQuery();

  const value = useMemo(
    () => ({ user, account, isLoading }),
    [user, account, isLoading],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }

  return context;
};
