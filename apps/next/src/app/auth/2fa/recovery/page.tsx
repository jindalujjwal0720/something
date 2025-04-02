import VerifyRecoveryCodeForm from '@/features/auth/components/forms/verfiy-recovery-code-form';
import { setAccessToken, setRole } from '@/features/auth/stores/auth';
import { Verify2faOtpResponse } from '@/features/auth/types/api/auth';
import { useRouter, useSearchParams } from 'next/navigation';
import { useDispatch } from 'react-redux';

const VerifyRecoveryCode = () => {
  const dispatch = useDispatch();
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectUri = searchParams.get('redirect_uri') || '';

  const handleSuccessfulLogin = (data: Verify2faOtpResponse) => {
    dispatch(setAccessToken(data.token));
    dispatch(setRole(data.account.roles[0]));
    router.replace(redirectUri || '/');
  };

  return <VerifyRecoveryCodeForm onSuccess={handleSuccessfulLogin} />;
};

export default VerifyRecoveryCode;
