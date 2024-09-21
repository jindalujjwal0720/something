import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { toast } from 'sonner';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Link, Navigate } from 'react-router-dom';
import { useResetPasswordMutation } from '../../api/auth';
import { getErrorMessage } from '@/utils/errors';

const resetPasswordFormSchema = z
  .object({
    newPassword: z
      .string()
      .min(8)
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
        {
          message:
            'Password must contain at least 8 characters, one uppercase, one lowercase, one number and one special character (@$!%*?&)',
        },
      ),
    confirmPassword: z.string(),
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

type ResetPasswordFormValues = z.infer<typeof resetPasswordFormSchema>;

interface ResetPasswordFormProps {
  token?: string;
  email?: string;
}

const ResetPasswordForm = ({ token, email }: ResetPasswordFormProps) => {
  const form = useForm<ResetPasswordFormValues>({
    resolver: zodResolver(resetPasswordFormSchema),
    defaultValues: {
      newPassword: '',
      confirmPassword: '',
    },
  });
  const [resetPassword] = useResetPasswordMutation();

  if (!token || !email) {
    return <Navigate to="/" />;
  }

  const onSubmit = async (data: ResetPasswordFormValues) => {
    try {
      const payload = await resetPassword({
        user: {
          email: email || '',
          currentPasswordOrToken: token,
          newPassword: data.newPassword,
          confirmPassword: data.confirmPassword,
        },
      }).unwrap();
      toast.success(payload.message);
    } catch (err) {
      toast.error(getErrorMessage(err));
    }
  };

  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle className="text-2xl">Reset Password</CardTitle>
        <CardDescription>
          Enter a new password for your account <strong>{email}</strong> below.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="newPassword"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>New password</FormLabel>
                  <FormControl>
                    <Input
                      type="password"
                      placeholder="Your password"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="confirmPassword"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Confirm password</FormLabel>
                  <FormControl>
                    <Input
                      type="password"
                      placeholder="Confirm your password"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button type="submit" className="w-full lg:col-span-2">
              Reset password
            </Button>
          </form>
        </Form>
        <div className="mt-4 text-center text-sm">
          Remember your password?{' '}
          <Link to="/auth/login" className="underline">
            Log in
          </Link>
        </div>
      </CardContent>
    </Card>
  );
};

export default ResetPasswordForm;
