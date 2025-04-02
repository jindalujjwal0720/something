import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb';
import UpdateRecoveryEmailForm from '@/features/auth/components/forms/update-recovery-email-form';

const UpdateRecoveryEmail = () => {
  return (
    <div className="flex flex-col gap-8">
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink href="/settings/security">Security</BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbPage>Update recovery email</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>
      <div>
        <h3 className="text-lg font-medium">Recovery email</h3>
        <p className="text-sm text-muted-foreground">
          Add an email address to recover your account. You can use this email
          address to recover your account if you forget your password or lose
          access to your account.
        </p>
      </div>
      <UpdateRecoveryEmailForm />
    </div>
  );
};

export default UpdateRecoveryEmail;
