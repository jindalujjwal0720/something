'use client';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { useAuth } from '@/features/auth/components/auth-provider';
import { CheckCircledIcon } from '@radix-ui/react-icons';
import { useRouter } from 'next/navigation';

const AccountRecoveryDetails = () => {
  const { account } = useAuth();
  const router = useRouter();

  return (
    <Card>
      <CardHeader>
        <CardTitle>Account recovery</CardTitle>
        <CardDescription>
          Set up account recovery options to help you recover your account in
          case you forget your password or lose access to your account.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="divide-y-2 space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div className="space-y-1">
              <h4 className="text-sm font-medium">Recovery email address</h4>
              <p className="text-sm text-muted-foreground flex gap-1 items-center">
                <span>
                  {account?.recoveryDetails?.email ||
                    'Add an email address to recover your account.'}
                </span>
                {account?.recoveryDetails?.emailVerified && (
                  <CheckCircledIcon className="size-4 text-green-600" />
                )}
              </p>
            </div>
            <Button
              variant="ghost"
              onClick={() => router.push('/settings/security/recovery/email')}
            >
              {account?.recoveryDetails?.email ? 'Change' : 'Add'} recovery
              email
            </Button>
          </div>
          <div className="flex pt-4 items-center justify-between gap-4">
            <div className="space-y-1">
              <h4 className="text-sm font-medium">Backup codes</h4>
              <p className="text-sm text-muted-foreground">
                {typeof account?.recoveryDetails?.backupCodesUsedCount !==
                'undefined'
                  ? `${account?.recoveryDetails?.backupCodesUsedCount} backup codes used`
                  : 'Generate backup codes to recover your account.'}
              </p>
            </div>
            <Button
              variant="ghost"
              onClick={() => router.push('/settings/security/recovery/codes')}
            >
              {typeof account?.recoveryDetails?.backupCodesUsedCount !==
              'undefined'
                ? 'Regenerate backup codes'
                : 'Generate backup codes'}
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default AccountRecoveryDetails;
