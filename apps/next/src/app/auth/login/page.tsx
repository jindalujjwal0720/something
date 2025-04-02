'use client';
import LoginForm from '@/features/auth/components/forms/login-form';
import { setAccessToken, setRole } from '@/features/auth/stores/auth';
import { LoginResponse } from '@/features/auth/types/api/auth';
import { useRouter } from 'next/navigation';
import { useDispatch } from 'react-redux';

const LoginPage = () => {
  const dispatch = useDispatch();
  const router = useRouter();

  const handleSuccessfulLogin = (response: LoginResponse) => {
    if ('requires2FA' in response) {
      router.replace(`/auth/2fa?token=${response.token}`);
    } else {
      dispatch(setAccessToken(response.token));
      dispatch(setRole(response.account.roles[0]));
      router.push('/');
    }
  };

  return <LoginForm onSuccess={handleSuccessfulLogin} />;
};

export default LoginPage;
