import ResetPasswordForm from '@/features/auth/components/forms/reset-password-form';
import useQueryParam from '@/hooks/useQueryParam';

const ResetPassword = () => {
  const token = useQueryParam('token');
  const email = useQueryParam('email');

  return (
    <div className="flex items-center justify-center h-screen bg-gray-50">
      <ResetPasswordForm token={token} email={email} />
    </div>
  );
};

export default ResetPassword;
