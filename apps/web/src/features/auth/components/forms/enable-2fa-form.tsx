import { Button } from '@/components/ui/button';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import {
  useDisable2FAMutation,
  useEnable2FAMutation,
  useGetMeQuery,
} from '../../api/auth';
import { getErrorMessage } from '@/utils/errors';
import { CheckCircledIcon } from '@radix-ui/react-icons';

const enable2faFormSchema = z.object({
  password: z.string(),
});

type Enable2faFormValues = z.infer<typeof enable2faFormSchema>;

const EnableTwoFactorAuthenticationForm = () => {
  const form = useForm<Enable2faFormValues>({
    resolver: zodResolver(enable2faFormSchema),
    defaultValues: {
      password: '',
    },
  });
  const { data: { user } = {} } = useGetMeQuery();
  const [enable2fa] = useEnable2FAMutation();
  const [disable2fa] = useDisable2FAMutation();

  const onSubmit = async (data: Enable2faFormValues) => {
    try {
      const payload = user?.twoFactorAuth?.enabled
        ? await disable2fa({
            password: data.password,
            email: user?.email || '',
          }).unwrap()
        : await enable2fa({
            password: data.password,
            email: user?.email || '',
          }).unwrap();
      toast.success(payload.message);
    } catch (err) {
      toast.error(getErrorMessage(err));
    }
  };

  return (
    <>
      {user?.twoFactorAuth?.enabled && (
        <p className="text-green-600 flex gap-2 text-sm items-center">
          <CheckCircledIcon />
          <span>Two-factor authentication is already enabled.</span>
        </p>
      )}
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">
          <FormField
            control={form.control}
            name="password"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Confirm your password</FormLabel>
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
          <Button
            type="submit"
            variant={user?.twoFactorAuth?.enabled ? 'secondary' : 'default'}
          >
            {user?.twoFactorAuth?.enabled ? 'Disable' : 'Enable'} two-factor
            authentication
          </Button>
        </form>
      </Form>
    </>
  );
};

export default EnableTwoFactorAuthenticationForm;
