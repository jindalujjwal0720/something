import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { toast } from 'sonner';
import { zodResolver } from '@hookform/resolvers/zod';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { z } from 'zod';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { useForm } from 'react-hook-form';
import { useResetPasswordMutation } from '../../api/auth';
import { getErrorMessage } from '@/utils/errors';
import { ResetPasswordResponse } from '../../types/api/auth';
import { useAuth } from '../auth-provider';

const changePasswordSchema = z
  .object({
    currentPassword: z.string(),
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

type ChangePasswordFormValues = z.infer<typeof changePasswordSchema>;

interface ChangePasswordFormProps {
  onSuccess?: (data: ResetPasswordResponse) => void;
}

const ChangePasswordForm = ({ onSuccess }: ChangePasswordFormProps) => {
  const form = useForm<ChangePasswordFormValues>({
    resolver: zodResolver(changePasswordSchema),
    defaultValues: {
      currentPassword: '',
      newPassword: '',
      confirmPassword: '',
    },
  });
  const { user } = useAuth();
  const [resetPassword] = useResetPasswordMutation();

  const onSubmit = async (data: ChangePasswordFormValues) => {
    try {
      const payload = await resetPassword({
        user: {
          email: user?.email || '',
          currentPasswordOrToken: data.currentPassword,
          newPassword: data.newPassword,
          confirmPassword: data.confirmPassword,
        },
      }).unwrap();
      toast.success(payload.message);
      if (onSuccess) {
        onSuccess(payload);
      }
    } catch (err) {
      toast.error(getErrorMessage(err));
    }
  };

  const onFormReset = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    form.reset();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Change password</CardTitle>
        <CardDescription>
          Update your password. Make sure it's unique and hard to guess.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex gap-4 justify-between">
          <Form {...form}>
            <form
              onSubmit={form.handleSubmit(onSubmit)}
              className="space-y-6 flex-1"
            >
              <FormField
                control={form.control}
                name="currentPassword"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Current password</FormLabel>
                    <FormControl>
                      <Input
                        type="password"
                        placeholder="Current password"
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="newPassword"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>New password</FormLabel>
                    <FormControl>
                      <Input
                        type="password"
                        placeholder="New password"
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
                        placeholder="Confirm password"
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <div className="flex space-x-4">
                <Button type="submit">Update password</Button>
                <Button variant="outline" onClick={onFormReset}>
                  Cancel
                </Button>
              </div>
            </form>
          </Form>
          <div className="w-max max-w-52">
            <div className="rounded-lg bg-muted p-4 space-y-3">
              <h3 className="text-sm font-medium">Password requirements</h3>
              <p className="text-xs">
                Your password must meet the following requirements:
              </p>
              <ul className="list-disc list-inside text-xs">
                <li>At least 8 characters</li>
                <li>One uppercase letter</li>
                <li>One lowercase letter</li>
                <li>One number</li>
                <li>One special character</li>
              </ul>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default ChangePasswordForm;
