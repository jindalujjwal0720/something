import { Navigate, Route, Routes } from 'react-router-dom';
import Login from './login';
import Register from './register';
import ForgotPassword from './forgot-password';
import ResetPassword from './reset-password';
import Verify2FAOTP from './verify-2fa-otp';
import Verify2FAAuthenticator from './verify-2fa-authenticator';
import Choose2FALoginMethod from './choose-2fa-method';
import useQueryParam from '@/hooks/useQueryParam';
import useLocationState from '@/hooks/useLocationState';
import { useSelector } from 'react-redux';
import { selectIsAuthenticated } from '@/features/auth/stores/auth';
import Verify2FARecoveryOTP from './verify-2fa-recovery-otp';
import VerifyRecoveryCode from './verify-recovery-code';

const Auth = () => {
  const isAuthenticated = useSelector(selectIsAuthenticated);
  const action = useQueryParam('action');
  const from = useLocationState('from');

  if (isAuthenticated && action !== 'new') {
    return <Navigate to={from || '/'} />;
  }

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/forgot" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route path="/2fa" element={<Choose2FALoginMethod />} />
      <Route path="/2fa/otp" element={<Verify2FAOTP />} />
      <Route path="/2fa/totp" element={<Verify2FAAuthenticator />} />
      <Route path="/2fa/recovery/email" element={<Verify2FARecoveryOTP />} />
      <Route path="/2fa/recovery" element={<VerifyRecoveryCode />} />
    </Routes>
  );
};

export default Auth;
