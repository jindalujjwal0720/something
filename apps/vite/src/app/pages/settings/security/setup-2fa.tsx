import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb';
import SetupTwoFactorAuthenticationForm from '@/features/auth/components/forms/setup-2fa-form';

const SetupTwoFactorAuthentication = () => {
  return (
    <div className="flex flex-col gap-8">
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink href="/settings/security">Security</BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbPage>Setup 2FA</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>
      <div>
        <h3 className="text-lg font-medium">Two-factor Authentication</h3>
        <p className="text-sm text-muted-foreground">
          Add an extra layer of security to your account. When enabled, you will
          need to provide a verification code along with your password when
          signing in.
        </p>
      </div>
      <SetupTwoFactorAuthenticationForm />
    </div>
  );
};

export default SetupTwoFactorAuthentication;
