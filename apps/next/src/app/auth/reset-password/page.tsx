import ResetPasswordForm from '@/features/auth/components/forms/reset-password-form';
import { useSearchParams } from 'next/navigation';

const ResetPassword = () => {
  const searchParams = useSearchParams();
  const token = searchParams.get('token') || '';
  const email = searchParams.get('email') || '';

  return <ResetPasswordForm token={token} email={email} />;
};

export default ResetPassword;
