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
import { useRouter } from 'next/navigation';

const TwoFactorAuthenticationDetails = () => {
  const { account } = useAuth();
  const router = useRouter();

  return (
    <Card>
      <CardHeader>
        <CardTitle>Two-factor Authentication</CardTitle>
        <CardDescription>
          Two-factor authentication(2FA) is an additional security step to
          verify your identity. Currently, we support{' '}
          <strong>Email OTPs</strong> and <strong>Authenticator apps</strong>.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="divide-y-2 flex flex-col gap-4">
          <div className="pb-4 flex items-center justify-between gap-4">
            <div className="flex flex-col gap-1">
              <h4 className="text-sm font-medium">
                Enable two-factor authentication
              </h4>
            </div>
            <Button
              onClick={() => router.push('/settings/security/2fa')}
              variant={account?.twoFactorAuth?.enabled ? 'ghost' : 'default'}
            >
              {account?.twoFactorAuth?.enabled ? 'Disable' : 'Enable'}
            </Button>
          </div>
          <div className="pb-4 flex items-center justify-between gap-4">
            <div className="flex flex-col gap-1">
              <h4 className="text-sm font-medium">
                Authenticator apps (recommended)
              </h4>
              <p className="text-sm text-muted-foreground">
                Use an authenticator app to generate one-time passwords.
              </p>
            </div>
            <Button
              variant="ghost"
              disabled={!account?.twoFactorAuth?.enabled}
              onClick={() => router.push('/settings/security/authenticator')}
            >
              {account?.twoFactorAuth?.totp?.enabled ? 'Enabled' : 'Setup'}
            </Button>
          </div>
          <div className="flex items-center justify-between gap-4">
            <div className="flex flex-col gap-1">
              <h4 className="text-sm font-medium">Email one-time passwords</h4>
              <p className="text-sm text-muted-foreground">
                Default method for two-factor authentication.
              </p>
            </div>
            <Button variant="ghost" disabled={true}>
              Enabled
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default TwoFactorAuthenticationDetails;
