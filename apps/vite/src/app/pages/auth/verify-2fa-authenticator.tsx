import Verify2faAuthenticatorForm from '@/features/auth/components/forms/verify-2fa-authenticator-form';
import { setAccessToken, setRole } from '@/features/auth/stores/auth';
import { Verify2faTotpResponse } from '@/features/auth/types/api/auth';
import useQueryParam from '@/hooks/useQueryParam';
import { useDispatch } from 'react-redux';
import { useNavigate } from 'react-router-dom';

const Verify2FAAuthenticator = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const redirectUri = useQueryParam('redirect_uri');

  const handleSuccessfulLogin = (data: Verify2faTotpResponse) => {
    dispatch(setAccessToken(data.token));
    dispatch(setRole(data.account.roles[0]));
    navigate(redirectUri || '/');
  };

  return (
    <div className="flex items-center justify-center h-screen bg-gray-50">
      <Verify2faAuthenticatorForm onSuccess={handleSuccessfulLogin} />
    </div>
  );
};

export default Verify2FAAuthenticator;
