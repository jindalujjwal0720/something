'use client';
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
import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import QRCode from 'react-qr-code';
import { Card, CardContent } from '@/components/ui/card';
import {
  useEnable2faTotpMutation,
  useRegenerate2faTotpMutation,
} from '../../api/auth';
import { toast } from 'sonner';
import { getErrorMessage } from '@/utils/errors';
import { useAuth } from '../auth-provider';

const setup2faAuthenticatorFormSchema = z.object({
  password: z.string(),
});

type Setup2faAuthenticatorFormValues = z.infer<
  typeof setup2faAuthenticatorFormSchema
>;

const Setup2faAuthenticatorForm = () => {
  const form = useForm<Setup2faAuthenticatorFormValues>({
    resolver: zodResolver(setup2faAuthenticatorFormSchema),
    defaultValues: {
      password: '',
    },
  });
  const { account } = useAuth();
  const [enableTotp, { isLoading }] = useEnable2faTotpMutation();
  const [regenerateTotp, { isLoading: isRegeneratingTotp }] =
    useRegenerate2faTotpMutation();
  const [otpAuthUrl, setOtpAuthUrl] = useState<string | null>(null);

  const onSubmit = async (_data: Setup2faAuthenticatorFormValues) => {
    if (isLoading) return;
    try {
      const data = form.getValues();
      if (account?.twoFactorAuth?.totp.enabled) {
        const response = await regenerateTotp({
          email: account?.email || '',
          password: data.password,
        }).unwrap();
        setOtpAuthUrl(response.otpAuthUrl);
      } else {
        const response = await enableTotp({
          email: account?.email || '',
          password: data.password,
        }).unwrap();
        setOtpAuthUrl(response.otpAuthUrl);
      }
      form.reset();
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
        {!isLoading ? (
          otpAuthUrl && (
            <>
              <div className="flex gap-6 items-center">
                <Card className="w-min">
                  <CardContent className="p-4">
                    <QRCode value={otpAuthUrl} size={200} />
                  </CardContent>
                </Card>
                <p className="text-sm text-muted-foreground">
                  <span className="font-semibold">
                    Important: This won't be shown again.
                  </span>{' '}
                  Scan the QR code using your authenticator app to set up
                  two-factor authentication.
                </p>
              </div>
            </>
          )
        ) : (
          <p className="text-muted-foreground">Generating QR code...</p>
        )}
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
          <Button type="submit" disabled={isLoading || isRegeneratingTotp}>
            {account?.twoFactorAuth?.totp.enabled
              ? 'Re-generate QR code'
              : 'Generate QR code'}
          </Button>
        </div>
      </form>
    </Form>
  );
};

export default Setup2faAuthenticatorForm;
