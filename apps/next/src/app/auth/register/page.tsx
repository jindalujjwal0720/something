'use client';
import RegisterForm from '@/features/auth/components/forms/register-form';
import { RegisterResponse } from '@/features/auth/types/api/auth';
import { useRouter } from 'next/navigation';

const Register = () => {
  const router = useRouter();

  const handleSuccess = (data: RegisterResponse) => {
    // Redirect to login page
    const query = new URLSearchParams({
      action: 'verify_email',
      email: data.account.email,
    }).toString();

    router.replace(`/auth/login?${query}`);
  };

  return <RegisterForm onSuccess={handleSuccess} />;
};

export default Register;
