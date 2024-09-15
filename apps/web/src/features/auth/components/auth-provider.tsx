import { PropsWithChildren } from 'react';
import { useGetMeQuery } from '../api/auth';
import Loading from '@/components/loading';

const AuthProvider = ({ children }: PropsWithChildren) => {
  const { isLoading } = useGetMeQuery();

  return isLoading ? <Loading /> : children;
};

export default AuthProvider;
