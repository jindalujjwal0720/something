import AccountRecoveryDetails from '@/features/settings/components/account-recovery-details';
import ChangePasswordForm from '@/features/auth/components/forms/change-password-form';
import TwoFactorAuthenticationDetails from '@/features/settings/components/two-factor-auth-details';

const Security = () => {
  return (
    <div className="flex flex-col gap-8">
      <div>
        <h3 className="text-lg font-medium">Security</h3>
        <p className="text-sm text-muted-foreground">
          Update your security settings. Change your password and enable
          two-factor authentication.
        </p>
      </div>
      <TwoFactorAuthenticationDetails />
      <AccountRecoveryDetails />
      <ChangePasswordForm />
    </div>
  );
};

export default Security;
