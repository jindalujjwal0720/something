import { Route, Routes } from 'react-router-dom';
import Login from './login';
import Register from './register';
import ForgotPassword from './forgot-password';
import ResetPassword from './reset-password';
import Verify2FAOTP from './verify-2fa-otp';
import Verify2FAAuthenticator from './verify-2fa-authenticator';
import Choose2FALoginMethod from './choose-2fa-method';

const Auth = () => {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/forgot" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route path="/2fa" element={<Choose2FALoginMethod />} />
      <Route path="/2fa/otp" element={<Verify2FAOTP />} />
      <Route path="/2fa/totp" element={<Verify2FAAuthenticator />} />
    </Routes>
  );
};

export default Auth;
