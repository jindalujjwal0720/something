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
import { getErrorMessage } from '@/utils/errors';

const Choose2FALoginMethodForm = () => {
  const token = useQueryParam('token');
  const {
    data: { methods } = {},
    isLoading,
    error,
  } = useGet2FALoginMethodsQuery(token ?? '', {
    skip: !token,
  });

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
          {error && (
            <p className="text-sm text-destructive">{getErrorMessage(error)}</p>
          )}
          {methods?.includes('totp') && (
            <Link
              to={`/auth/2fa/totp?token=${token}`}
              className="flex gap-4 px-3 py-4 rounded-md hover:bg-muted cursor-pointer"
            >
              <MobileIcon className="w-6 h-max" />
              <div className="flex-1">
                <p className="text-sm font-medium">Use an authenticator app</p>
                <p className="text-xs text-muted-foreground">
                  Use a time-based one-time passcode from an authenticator app
                </p>
              </div>
            </Link>
          )}
          {methods?.includes('otp') && (
            <Link
              to={`/auth/2fa/otp?token=${token}`}
              className="flex gap-4 px-3 py-4 rounded-md hover:bg-muted cursor-pointer"
            >
              <EnvelopeClosedIcon className="w-5" />
              <div className="flex-1">
                <p className="text-sm font-medium">Get a code via email</p>
                <p className="text-xs text-muted-foreground">
                  Get a one-time passcode sent to your email address
                </p>
              </div>
            </Link>
          )}
          {methods?.includes('recovery-email') && (
            <Link
              to={`/auth/2fa/recovery/email?token=${token}`}
              className="flex gap-4 px-3 py-4 rounded-md hover:bg-muted cursor-pointer"
            >
              <EnvelopeClosedIcon className="w-5" />
              <div className="flex-1">
                <p className="text-sm font-medium">Use recovery email</p>
                <p className="text-xs text-muted-foreground">
                  Get a one-time passcode sent to your recovery email address
                </p>
              </div>
            </Link>
          )}
          {methods?.includes('recovery') && (
            <Link
              to={`/auth/2fa/recovery?token=${token}`}
              className="flex gap-4 px-3 py-4 rounded-md hover:bg-muted cursor-pointer"
            >
              <LockClosedIcon className="w-5" />
              <div className="flex-1">
                <p className="text-sm font-medium">Use recovery code</p>
                <p className="text-xs text-muted-foreground">
                  Use a recovery code to sign in
                </p>
              </div>
            </Link>
          )}
        </div>
      </CardContent>
      <CardFooter>
        <div className="text-center text-sm">
          Go back to{' '}
          <Link to="/auth/login" className="underline">
            login page
          </Link>
        </div>
      </CardFooter>
    </Card>
  );
};

export default Choose2FALoginMethodForm;
