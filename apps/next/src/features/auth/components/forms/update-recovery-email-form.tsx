'use client';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { useRequestUpdateRecoveryEmailMutation } from '../../api/auth';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { getErrorMessage } from '@/utils/errors';
import { toast } from 'sonner';
import { CheckCircledIcon } from '@radix-ui/react-icons';
import { useAuth } from '../auth-provider';

const updateRecoveryEmailFormSchema = z.object({
  recoveryEmail: z.string().email(),
  password: z.string().min(1, "Password can't be empty"),
});

type UpdateRecoveryEmailFormValues = z.infer<
  typeof updateRecoveryEmailFormSchema
>;

const UpdateRecoveryEmailForm = () => {
  const { account } = useAuth();
  const form = useForm<UpdateRecoveryEmailFormValues>({
    resolver: zodResolver(updateRecoveryEmailFormSchema),
    defaultValues: {
      recoveryEmail: account?.recoveryDetails?.email || '',
      password: '',
    },
  });
  const [requestUpdateRecoveryEmail] = useRequestUpdateRecoveryEmailMutation();

  const onSubmit = async (data: UpdateRecoveryEmailFormValues) => {
    if (form.getValues('recoveryEmail') === account?.recoveryDetails?.email) {
      toast.info('Recovery email is already set.');
      return;
    }
    try {
      const payload = await requestUpdateRecoveryEmail({
        email: account?.email || '',
        newRecoveryEmail: data.recoveryEmail,
        password: data.password,
      }).unwrap();
      form.reset();
      toast.success(payload.message);
    } catch (err) {
      toast.error(getErrorMessage(err));
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmit)}
        className="flex flex-col gap-8"
      >
        <FormField
          control={form.control}
          name="recoveryEmail"
          render={({ field }) => (
            <FormItem>
              <FormLabel className="flex gap-2">
                <span>Recovery email</span>
                {field.value === account?.recoveryDetails?.email && (
                  <CheckCircledIcon className="size-4 text-green-600" />
                )}
              </FormLabel>
              <FormControl>
                <Input
                  type="email"
                  placeholder="Your recovery email"
                  {...field}
                  className={
                    field.value === account?.recoveryDetails?.email
                      ? 'font-medium'
                      : ''
                  }
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="password"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Confirm your password</FormLabel>
              <FormControl>
                <Input type="password" placeholder="Your password" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <div className="flex gap-4 flex-col md:flex-row">
          <Button type="submit">Update recovery email</Button>
        </div>
      </form>
    </Form>
  );
};

export default UpdateRecoveryEmailForm;
