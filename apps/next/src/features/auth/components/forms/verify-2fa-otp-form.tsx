'use client';
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
import { useSend2faOtpMutation, useVerify2faOtpMutation } from '../../api/auth';
import { toast } from 'sonner';
import { REGEXP_ONLY_DIGITS } from 'input-otp';
import { Verify2faOtpResponse } from '../../types/api/auth';
import useTimer from '../../hooks/useTimer';
import { convertDurationToReadable } from '@/utils/time';
import { useCallback } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';

const verify2faOtpSchema = z.object({
  otp: z.string().length(6, {
    message: 'OTP must be 6 characters',
  }),
});

type Verify2FAOTPFormValues = z.infer<typeof verify2faOtpSchema>;

interface Verify2FAOTPFormProps {
  onSuccess?: (data: Verify2faOtpResponse) => void;
}

const Verify2FAOTPForm = ({ onSuccess }: Verify2FAOTPFormProps) => {
  const searchParams = useSearchParams();
  const token = searchParams.get('token');
  const form = useForm<Verify2FAOTPFormValues>({
    resolver: zodResolver(verify2faOtpSchema),
    defaultValues: {
      otp: '',
    },
  });
  const [sendOtp, { isLoading: isSendingOtp }] = useSend2faOtpMutation();
  const [verifyOTP, { isLoading: isVerifyingOtp }] = useVerify2faOtpMutation();
  const [timer, setTimer] = useTimer(0);

  const onSubmit = async (data: Verify2FAOTPFormValues) => {
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

  const handleSendOtp = useCallback(async () => {
    try {
      const payload = await sendOtp({ token: token || '' }).unwrap();
      const seconds = (new Date(payload.expires).getTime() - Date.now()) / 1000;
      setTimer(seconds);
      toast.success(payload.message);
    } catch (err) {
      toast.error(getErrorMessage(err));
    }
  }, [sendOtp, token, setTimer]);

  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle className="text-2xl">Verify OTP</CardTitle>
        <CardDescription>
          Please enter the One-time-password sent to your email address.
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
          Didn't receive the OTP?{' '}
          <Button
            variant="link"
            onClick={handleSendOtp}
            disabled={isSendingOtp || timer > 0}
            className="p-0 h-8 underline"
          >
            Resend OTP {timer > 0 && `in ${convertDurationToReadable(timer)}`}
          </Button>
        </div>
        <div className="mt-4 text-center text-sm">
          Choose a{' '}
          <Link href={`/auth/2fa?token=${token}`} className="underline">
            different method
          </Link>{' '}
          or go back to{' '}
          <Link href="/auth/login" className="underline">
            login
          </Link>
        </div>
      </CardContent>
    </Card>
  );
};

export default Verify2FAOTPForm;
