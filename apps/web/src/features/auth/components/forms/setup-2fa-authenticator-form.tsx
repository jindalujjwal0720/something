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
  const [otpAuthUrl, setOtpAuthUrl] = useState<string | null>(null);

  const onSubmit = (_data: Setup2faAuthenticatorFormValues) => {
    setOtpAuthUrl((prev) => {
      return prev ? null : 'otpauth://totp/MyApp:alice?secret=JBS';
    });
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">
        {otpAuthUrl && (
          <>
            <div className="flex gap-6 items-center">
              <Card className="w-min">
                <CardContent className="p-4">
                  <QRCode value={otpAuthUrl} size={200} />
                </CardContent>
              </Card>
              <p className="text-sm text-muted-foreground">
                Scan the QR code using your authenticator app to set up
                two-factor authentication.
              </p>
            </div>
          </>
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
        <Button type="submit">
          {otpAuthUrl ? 'Re-generate QR code' : 'Generate QR code'}
        </Button>
      </form>
    </Form>
  );
};

export default Setup2faAuthenticatorForm;
