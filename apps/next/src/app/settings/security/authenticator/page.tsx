import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb';
import Setup2faAuthenticatorForm from '@/features/auth/components/forms/setup-2fa-authenticator-form';

const SetupAuthenticator = () => {
  return (
    <div className="space-y-8">
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink href="/settings/security">Security</BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbPage>Setup Authenticator</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>
      <div>
        <h3 className="text-lg font-medium">Setup Authenticator app</h3>
        <p className="text-sm text-muted-foreground">
          Set up two-factor authentication using an authenticator app like
          <strong> Google Authenticator</strong> or <strong>Authy</strong>.
        </p>
      </div>
      <Setup2faAuthenticatorForm />
    </div>
  );
};

export default SetupAuthenticator;
