import { createContext, PropsWithChildren, useContext, useMemo } from 'react';
import { authClient, Session } from '@/utils/auth-client';

interface AuthContextValue {
  session: Session | null;
  isLoading: boolean;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider = ({ children }: PropsWithChildren) => {
  const { data: session, isPending } = authClient.useSession();

  const value = useMemo(() => {
    return {
      session,
      isLoading: isPending,
      isAuthenticated: !!session,
    };
  }, [session, isPending]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }

  return context;
};
