import VerifyRecoveryCodeForm from '@/features/auth/components/forms/verfiy-recovery-code-form';
import { setAccessToken, setRole } from '@/features/auth/stores/auth';
import { Verify2faOtpResponse } from '@/features/auth/types/api/auth';
import useQueryParam from '@/hooks/useQueryParam';
import { useDispatch } from 'react-redux';
import { useNavigate } from 'react-router-dom';

const VerifyRecoveryCode = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const redirectUri = useQueryParam('redirect_uri');

  const handleSuccessfulLogin = (data: Verify2faOtpResponse) => {
    dispatch(setAccessToken(data.token));
    dispatch(setRole(data.account.roles[0]));
    navigate(redirectUri || '/');
  };

  return (
    <div className="flex items-center justify-center h-screen bg-gray-50">
      <VerifyRecoveryCodeForm onSuccess={handleSuccessfulLogin} />
    </div>
  );
};

export default VerifyRecoveryCode;
