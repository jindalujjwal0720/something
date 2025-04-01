import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { useAuth } from '@/features/auth/components/auth-provider';
import { useNavigate } from 'react-router-dom';

const TwoFactorAuthenticationDetails = () => {
  const { account } = useAuth();
  const navigate = useNavigate();

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
        <div className="divide-y-2 space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div className="space-y-1">
              <h4 className="text-sm font-medium">
                Enable two-factor authentication
              </h4>
            </div>
            <Button
              onClick={() => navigate('/settings/security/2fa')}
              variant={account?.twoFactorAuth?.enabled ? 'ghost' : 'default'}
            >
              {account?.twoFactorAuth?.enabled ? 'Disable' : 'Enable'}
            </Button>
          </div>
          <div className="flex pt-4 items-center justify-between gap-4">
            <div className="space-y-1">
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
              onClick={() => navigate('/settings/security/authenticator')}
            >
              {account?.twoFactorAuth?.totp?.enabled ? 'Enabled' : 'Setup'}
            </Button>
          </div>
          <div className="flex pt-4 items-center justify-between gap-4">
            <div className="space-y-1">
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
