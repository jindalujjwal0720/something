import { store } from '@/stores';
import { Provider as ReduxProvider } from 'react-redux';
import { Toaster as ShadCNToaster } from '@/components/ui/toaster';
import { Toaster as SonnerToaster } from '@/components/ui/sonner';
import { ThemeProvider } from '@/components/ui/theme-provider';
import AuthProvider from '@/features/auth/components/auth-provider';

export interface ProviderProps {
  children: React.ReactNode;
}

const Provider = ({ children }: ProviderProps) => {
  return (
    <>
      <ReduxProvider store={store}>
        <ThemeProvider
          defaultValue={{ font: 'inter', theme: 'light' }}
          storageKey="something-ui-theme"
        >
          <AuthProvider>{children}</AuthProvider>
        </ThemeProvider>
        <ShadCNToaster />
        <SonnerToaster />
      </ReduxProvider>
    </>
  );
};

export default Provider;
