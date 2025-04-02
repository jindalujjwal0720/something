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
  InputOTPSlot,
} from '@/components/ui/input-otp';
import { Button } from '@/components/ui/button';
import { getErrorMessage } from '@/utils/errors';
import { toast } from 'sonner';
import { REGEXP_ONLY_DIGITS } from 'input-otp';
import { Link } from 'react-router-dom';
import { useVerify2faTotpMutation } from '../../api/auth';
import { Verify2faTotpResponse } from '../../types/api/auth';
import useQueryParam from '@/hooks/useQueryParam';

const verifu2faAuthenticatorSchema = z.object({
  otp: z.string().length(6, {
    message: 'OTP must be 6 characters',
  }),
});

type Verify2faAuthenticatorFormValues = z.infer<
  typeof verifu2faAuthenticatorSchema
>;

interface Verify2faAuthenticatorFormProps {
  onSuccess?: (data: Verify2faTotpResponse) => void;
}

const Verify2faAuthenticatorForm = ({
  onSuccess,
}: Verify2faAuthenticatorFormProps) => {
  const token = useQueryParam('token');
  const form = useForm<Verify2faAuthenticatorFormValues>({
    resolver: zodResolver(verifu2faAuthenticatorSchema),
    defaultValues: {
      otp: '',
    },
  });
  const [verifyOTP, { isLoading: isVerifyingOtp }] = useVerify2faTotpMutation();

  const onSubmit = async (data: Verify2faAuthenticatorFormValues) => {
    try {
      const payload = await verifyOTP({
        otp: data.otp,
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
        <CardTitle className="text-2xl">Verify OTP</CardTitle>
        <CardDescription>
          Please enter the One-time-password from your{' '}
          <span className="font-semibold">Authenticator App</span>.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-12">
            <FormField
              control={form.control}
              name="otp"
              render={({ field }) => (
                <FormItem>
                  <FormControl>
                    <div className="flex justify-center">
                      <InputOTP
                        {...field}
                        maxLength={6}
                        pattern={REGEXP_ONLY_DIGITS}
                      >
                        <InputOTPGroup>
                          <InputOTPSlot index={0} />
                          <InputOTPSlot index={1} />
                          <InputOTPSlot index={2} />
                          <InputOTPSlot index={3} />
                          <InputOTPSlot index={4} />
                          <InputOTPSlot index={5} />
                        </InputOTPGroup>
                      </InputOTP>
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button type="submit" className="w-full" disabled={isVerifyingOtp}>
              {isVerifyingOtp ? 'Verifying...' : 'Verify OTP'}
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

export default Verify2faAuthenticatorForm;
