import RegisterForm from '@/features/auth/components/forms/register-form';
import { RegisterResponse } from '@/features/auth/types/api/auth';
import { useNavigate } from 'react-router-dom';

const Register = () => {
  const navigate = useNavigate();

  const handleSuccess = (data: RegisterResponse) => {
    // Redirect to login page
    navigate('/auth/login', {
      state: {
        message: `Account created for ${data.user.email}. Please verify your email to login.`,
        email: data.user.email,
      },
    });
  };

  return (
    <div className="flex items-center justify-center h-screen bg-gray-50">
      <RegisterForm onSuccess={handleSuccess} />
    </div>
  );
};

export default Register;
