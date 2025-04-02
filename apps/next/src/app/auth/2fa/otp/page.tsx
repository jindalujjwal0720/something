'use client';
import Verify2FAOTPForm from '@/features/auth/components/forms/verify-2fa-otp-form';
import { setAccessToken, setRole } from '@/features/auth/stores/auth';
import { Verify2faOtpResponse } from '@/features/auth/types/api/auth';
import { useRouter, useSearchParams } from 'next/navigation';
import { useDispatch } from 'react-redux';

const Verify2FAOTP = () => {
  const dispatch = useDispatch();
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectUri = searchParams.get('redirect_uri') || '';

  const handleSuccessfulLogin = (data: Verify2faOtpResponse) => {
    dispatch(setAccessToken(data.token));
    dispatch(setRole(data.account.roles[0]));
    router.replace(redirectUri || '/');
  };

  return <Verify2FAOTPForm onSuccess={handleSuccessfulLogin} />;
};

export default Verify2FAOTP;
