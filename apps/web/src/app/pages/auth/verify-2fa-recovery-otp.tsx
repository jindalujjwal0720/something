import Verify2FARecoveryOTPForm from '@/features/auth/components/forms/verify-2fa-recovery-otp-form';
import { setAccessToken, setRole } from '@/features/auth/stores/auth';
import { Verify2faOtpResponse } from '@/features/auth/types/api/auth';
import { useDispatch } from 'react-redux';
import { useNavigate } from 'react-router-dom';

const Verify2FARecoveryOTP = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const handleSuccessfulLogin = (data: Verify2faOtpResponse) => {
    dispatch(setAccessToken(data.token));
    dispatch(setRole(data.user.roles[0]));
    navigate('/');
  };

  return (
    <div className="flex items-center justify-center h-screen bg-gray-50">
      <Verify2FARecoveryOTPForm onSuccess={handleSuccessfulLogin} />
    </div>
  );
};

export default Verify2FARecoveryOTP;
