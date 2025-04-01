import {
  Card,
  CardHeader,
  CardContent,
  CardTitle,
  CardDescription,
} from '@/components/ui/card';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormMessage,
} from '@/components/ui/form';
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSeparator,
  InputOTPSlot,
} from '@/components/ui/input-otp';
import { Button } from '@/components/ui/button';
import { getErrorMessage } from '@/utils/errors';
import { toast } from 'sonner';
import { REGEXP_ONLY_DIGITS_AND_CHARS } from 'input-otp';
import { Link } from 'react-router-dom';
import { useLoginWithRecoveryCodeMutation } from '../../api/auth';
import { Verify2faTotpResponse } from '../../types/api/auth';
import useQueryParam from '@/hooks/useQueryParam';

const verifyRecoveryCodeFormSchema = z.object({
  code: z.string().length(8, 'Recovery code must be 8 characters'),
});

type VerifyRecoveryCodeFormValues = z.infer<
  typeof verifyRecoveryCodeFormSchema
>;

interface VerifyRecoveryCodeFormProps {
  onSuccess?: (data: Verify2faTotpResponse) => void;
}

const VerifyRecoveryCodeForm = ({ onSuccess }: VerifyRecoveryCodeFormProps) => {
  const token = useQueryParam('token');
  const form = useForm<VerifyRecoveryCodeFormValues>({
    resolver: zodResolver(verifyRecoveryCodeFormSchema),
    defaultValues: {
      code: '',
    },
  });
  const [verifyRecoveryCode, { isLoading: isVerifyingOtp }] =
    useLoginWithRecoveryCodeMutation();

  const onSubmit = async (data: VerifyRecoveryCodeFormValues) => {
    try {
      const payload = await verifyRecoveryCode({
        code: data.code,
        token: token || '',
      }).unwrap();
      if (onSuccess) {
        onSuccess(payload);
      }
    } catch (err) {
      toast.error(getErrorMessage(err));
    }
  };

  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle className="text-2xl">Verify recovery code</CardTitle>
        <CardDescription>
          Enter the recovery code saved during the setup process.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-12">
            <FormField
              control={form.control}
              name="code"
              render={({ field }) => (
                <FormItem>
                  <FormControl>
                    <div className="flex justify-center">
                      <InputOTP
                        {...field}
                        maxLength={8}
                        pattern={REGEXP_ONLY_DIGITS_AND_CHARS}
                      >
                        <InputOTPGroup>
                          <InputOTPSlot index={0} />
                          <InputOTPSlot index={1} />
                          <InputOTPSlot index={2} />
                          <InputOTPSlot index={3} />
                        </InputOTPGroup>
                        <InputOTPSeparator />
                        <InputOTPGroup>
                          <InputOTPSlot index={4} />
                          <InputOTPSlot index={5} />
                          <InputOTPSlot index={6} />
                          <InputOTPSlot index={7} />
                        </InputOTPGroup>
                      </InputOTP>
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button type="submit" className="w-full" disabled={isVerifyingOtp}>
              {isVerifyingOtp ? 'Verifying...' : 'Verify recovery code'}
            </Button>
          </form>
        </Form>
        <div className="mt-4 text-center text-sm">
          Choose a{' '}
          <Link to={`/auth/2fa?token=${token}`} className="underline">
            different method
          </Link>{' '}
          or go back to{' '}
          <Link to="/auth/login" className="underline">
            login
          </Link>
        </div>
      </CardContent>
    </Card>
  );
};

export default VerifyRecoveryCodeForm;
