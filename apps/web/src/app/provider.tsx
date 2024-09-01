import { store } from '@/stores';
import { Provider as ReduxProvider } from 'react-redux';

export interface ProviderProps {
  children: React.ReactNode;
}

const Provider = ({ children }: ProviderProps) => {
  return (
    <>
      <ReduxProvider store={store}>{children}</ReduxProvider>
    </>
  );
};

export default Provider;
