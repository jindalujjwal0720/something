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
import { useState } from 'react';
import RecoveryCodes from '../recovery-codes';

const setup2faFormSchema = z.object({
  password: z.string(),
});

type Setup2faFormValues = z.infer<typeof setup2faFormSchema>;

const SetupTwoFactorAuthenticationForm = () => {
  const form = useForm<Setup2faFormValues>({
    resolver: zodResolver(setup2faFormSchema),
    defaultValues: {
      password: '',
    },
  });
  const { data: { user } = {} } = useGetMeQuery();
  const [enable2fa] = useEnable2FAMutation();
  const [disable2fa] = useDisable2FAMutation();
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);

  const onSubmit = async (data: Setup2faFormValues) => {
    try {
      if (user?.twoFactorAuth?.enabled) {
        const payload = await disable2fa({
          password: data.password,
          email: user?.email || '',
        }).unwrap();
        form.reset();
        toast.success(payload.message);
        return;
      } else {
        const payload = await enable2fa({
          password: data.password,
          email: user?.email || '',
        }).unwrap();
        form.reset();
        setRecoveryCodes(payload.recoveryCodes);
        toast.success('Two-factor authentication enabled.');
      }
    } catch (err) {
      toast.error(getErrorMessage(err));
    }
  };

  return (
    <>
      {user?.twoFactorAuth?.enabled && (
        <p className="text-green-600 flex gap-2 text-sm items-center">
          <CheckCircledIcon />
          <span>Two-factor authentication is enabled.</span>
        </p>
      )}
      {recoveryCodes && recoveryCodes.length > 0 && (
        <RecoveryCodes recoveryCodes={recoveryCodes} />
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
            variant={user?.twoFactorAuth?.enabled ? 'destructive' : 'default'}
          >
            {user?.twoFactorAuth?.enabled ? 'Disable' : 'Enable'} two-factor
            authentication
          </Button>
        </form>
      </Form>
    </>
  );
};

export default SetupTwoFactorAuthenticationForm;
