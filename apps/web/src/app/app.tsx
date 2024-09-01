import Provider from './provider';
import Router from './router';
import Pages from './pages';
import { Toaster as ShadCNToaster } from '@/components/ui/toaster';
import { Toaster as SonnerToaster } from '@/components/ui/sonner';
import { ThemeProvider } from '@/components/ui/theme-provider';

function App() {
  return (
    <>
      <Provider>
        <ThemeProvider
          defaultValue={{ font: 'inter', theme: 'light' }}
          storageKey="something-ui-theme"
        >
          <Router>
            <Pages />
          </Router>
        </ThemeProvider>
        <ShadCNToaster />
        <SonnerToaster />
      </Provider>
    </>
  );
}

export default App;
