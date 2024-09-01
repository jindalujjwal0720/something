import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb';
import EnableTwoFactorAuthenticationForm from '@/features/auth/components/forms/enable-2fa-form';

const EnableTwoFactorAuthentication = () => {
  return (
    <div className="space-y-8">
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink href="/settings/security">Security</BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbPage>Enable 2FA</BreadcrumbPage>
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
      <EnableTwoFactorAuthenticationForm />
    </div>
  );
};

export default EnableTwoFactorAuthentication;
