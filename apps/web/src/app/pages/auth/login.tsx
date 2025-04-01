import LoginForm from '@/features/auth/components/forms/login-form';
import { setAccessToken, setRole } from '@/features/auth/stores/auth';
import { LoginResponse } from '@/features/auth/types/api/auth';
import { useDispatch } from 'react-redux';
import { useNavigate } from 'react-router-dom';

const Login = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const handleSuccessfulLogin = (data: LoginResponse) => {
    if ('requires2FA' in data) {
      navigate(`/auth/2fa?token=${data.token}`);
    } else {
      dispatch(setAccessToken(data.token));
      dispatch(setRole(data.account.roles[0]));
      navigate('/');
    }
  };

  return (
    <div className="flex items-center justify-center h-screen bg-gray-50">
      <LoginForm onSuccess={handleSuccessfulLogin} />
    </div>
  );
};

export default Login;
