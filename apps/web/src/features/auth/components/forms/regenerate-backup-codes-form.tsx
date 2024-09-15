import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  useGetMeQuery,
  useRegenerateRecoveryCodesMutation,
} from '../../api/auth';
import { toast } from 'sonner';
import { getErrorMessage } from '@/utils/errors';
import { useState } from 'react';
import RecoveryCodes from '../recovery-codes';

const regenerateBackupCodesFormSchema = z.object({
  password: z.string().min(1, "Password can't be empty"),
});

type RegenerateBackupCodesFormValues = z.infer<
  typeof regenerateBackupCodesFormSchema
>;

const RegenerateBackupCodesForm = () => {
  const form = useForm<RegenerateBackupCodesFormValues>({
    resolver: zodResolver(regenerateBackupCodesFormSchema),
    defaultValues: {
      password: '',
    },
  });
  const [regenerateBackupCodes] = useRegenerateRecoveryCodesMutation();
  const { data: { user } = {} } = useGetMeQuery();
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);

  const onSubmit = async (data: RegenerateBackupCodesFormValues) => {
    try {
      const payload = await regenerateBackupCodes({
        password: data.password,
        email: user?.email || '',
      }).unwrap();
      form.reset();
      setRecoveryCodes(payload.recoveryCodes);
    } catch (err) {
      toast.error(getErrorMessage(err));
    }
  };

  return (
    <>
      <p className="text-sm text-muted-foreground">
        {user?.recoveryDetails?.backupCodesUsedCount} backup codes used so far.
        (Out of 10)
      </p>
      {recoveryCodes.length > 0 && (
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
                <FormDescription>
                  Regenerating backup codes will invalidate the existing backup
                  codes.
                </FormDescription>
              </FormItem>
            )}
          />
          <Button type="submit">Regenerate backup codes</Button>
        </form>
      </Form>
    </>
  );
};

export default RegenerateBackupCodesForm;
