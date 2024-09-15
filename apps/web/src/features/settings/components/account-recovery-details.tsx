import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { useGetMeQuery } from '@/features/auth/api/auth';
import { CheckCircledIcon } from '@radix-ui/react-icons';
import { useNavigate } from 'react-router-dom';

const AccountRecoveryDetails = () => {
  const { data: { user } = {} } = useGetMeQuery();
  const navigate = useNavigate();

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
                  {user?.recoveryDetails?.email ||
                    'Add an email address to recover your account.'}
                </span>
                {user?.recoveryDetails?.emailVerified && (
                  <CheckCircledIcon className="size-4 text-green-600" />
                )}
              </p>
            </div>
            <Button
              variant="ghost"
              onClick={() => navigate('/settings/security/recovery/email')}
            >
              {user?.recoveryDetails?.email ? 'Change' : 'Add'} recovery email
            </Button>
          </div>
          <div className="flex pt-4 items-center justify-between gap-4">
            <div className="space-y-1">
              <h4 className="text-sm font-medium">Backup codes</h4>
              <p className="text-sm text-muted-foreground">
                {typeof user?.recoveryDetails?.backupCodesUsedCount !==
                'undefined'
                  ? `${user?.recoveryDetails?.backupCodesUsedCount} backup codes used`
                  : 'Generate backup codes to recover your account.'}
              </p>
            </div>
            <Button
              variant="ghost"
              onClick={() => navigate('/settings/security/recovery/codes')}
            >
              {typeof user?.recoveryDetails?.backupCodesUsedCount !==
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
