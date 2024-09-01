import {
  Card,
  CardHeader,
  CardContent,
  CardTitle,
  CardDescription,
  CardFooter,
} from '@/components/ui/card';
import useQueryParam from '@/hooks/useQueryParam';
import {
  EnvelopeClosedIcon,
  LockClosedIcon,
  MobileIcon,
} from '@radix-ui/react-icons';
import { Link } from 'react-router-dom';
import { useGet2FALoginMethodsQuery } from '../../api/auth';

const Choose2FALoginMethodForm = () => {
  const token = useQueryParam('token');
  const { data: { methods } = {}, isLoading } = useGet2FALoginMethodsQuery(
    token ?? '',
    {
      skip: !token,
    },
  );

  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle>2 Step Verification</CardTitle>
        <CardDescription>
          To help keep your account safe, we want to make sure it's really you
          trying to sign in
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="divide-y-2">
          {isLoading && <p>Loading...</p>}
          {methods?.includes('totp') && (
            <Link
              to={`/auth/2fa/totp?token=${token}`}
              className="flex gap-4 px-3 py-4 rounded-md hover:bg-muted cursor-pointer text-muted-foreground hover:text-foreground"
            >
              <MobileIcon className="w-6 h-max" />
              <p className="text-sm">
                Use a time-based one-time passcode from an authenticator app
              </p>
            </Link>
          )}
          {methods?.includes('otp') && (
            <Link
              to={`/auth/2fa/otp?token=${token}`}
              className="flex gap-4 px-3 py-4 rounded-md hover:bg-muted cursor-pointer text-muted-foreground hover:text-foreground"
            >
              <EnvelopeClosedIcon className="w-5" />
              <p className="text-sm">
                We will send you a one-time code to your email address
              </p>
            </Link>
          )}
          {methods?.includes('recovery') && (
            <Link
              to={`/auth/2fa/recovery?token=${token}`}
              className="flex gap-4 px-3 py-4 rounded-md hover:bg-muted cursor-pointer text-muted-foreground hover:text-foreground"
            >
              <LockClosedIcon className="w-5" />
              <p className="text-sm">
                Use one of your recovery codes to sign in
              </p>
            </Link>
          )}
        </div>
      </CardContent>
      <CardFooter>
        <p className="text-xs text-muted-foreground">
          Lost your device or can't get a code?{' '}
          <Link to="/" className="underline">
            Learn more
          </Link>
        </p>
      </CardFooter>
    </Card>
  );
};

export default Choose2FALoginMethodForm;
