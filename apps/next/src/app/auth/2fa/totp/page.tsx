'use client';
import Verify2faAuthenticatorForm from '@/features/auth/components/forms/verify-2fa-authenticator-form';
import { setAccessToken, setRole } from '@/features/auth/stores/auth';
import { Verify2faTotpResponse } from '@/features/auth/types/api/auth';
import { useRouter, useSearchParams } from 'next/navigation';
import { useDispatch } from 'react-redux';

const Verify2FAAuthenticator = () => {
  const dispatch = useDispatch();
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectUri = searchParams.get('redirect_uri') || '';

  const handleSuccessfulLogin = (data: Verify2faTotpResponse) => {
    dispatch(setAccessToken(data.token));
    dispatch(setRole(data.account.roles[0]));
    router.replace(redirectUri || '/');
  };

  return <Verify2faAuthenticatorForm onSuccess={handleSuccessfulLogin} />;
};

export default Verify2FAAuthenticator;
