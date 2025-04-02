import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb';
import RegenerateBackupCodesForm from '@/features/auth/components/forms/regenerate-backup-codes-form';

const RegenerateBackupCodes = () => {
  return (
    <div className="space-y-8">
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink href="/settings/security">Security</BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbPage>Backup codes</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>
      <div>
        <h3 className="text-lg font-medium">Backup codes</h3>
        <p className="text-sm text-muted-foreground">
          Generate backup codes to recover your account. Save these backup codes
          in a safe place. You can use these codes to access your account if you
          lose access to your two-factor authentication device.
        </p>
      </div>
      <RegenerateBackupCodesForm />
    </div>
  );
};

export default RegenerateBackupCodes;
