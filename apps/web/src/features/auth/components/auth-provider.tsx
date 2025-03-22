import { createContext, PropsWithChildren, useContext, useMemo } from 'react';
import { useGetMeQuery } from '../api/auth';
import { IUser } from '@/types/models/user';

interface AuthContextValue {
  user: IUser | undefined;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider = ({ children }: PropsWithChildren) => {
  const { data: { user } = {}, isLoading } = useGetMeQuery();

  const value = useMemo(() => ({ user, isLoading }), [user, isLoading]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }

  return context;
};
