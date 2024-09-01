import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { toast } from '@/components/ui/use-toast';

const AccountRecoveryDetails = () => {
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
              <h4 className="text-sm font-medium">
                Add account recovery email
              </h4>
              <p className="text-sm text-muted-foreground">
                Add an email address to recover your account.
              </p>
            </div>
            <Button
              variant="ghost"
              onClick={() =>
                toast({
                  title: 'Account recovery email added',
                })
              }
            >
              Add recovery email
            </Button>
          </div>
          <div className="flex pt-4 items-center justify-between gap-4">
            <div className="space-y-1">
              <h4 className="text-sm font-medium">Add recovery phone number</h4>
              <p className="text-sm text-muted-foreground">
                Add a phone number to recover your account.
              </p>
            </div>
            <Button
              variant="ghost"
              onClick={() =>
                toast({
                  title: 'Account recovery phone number added',
                })
              }
            >
              Add recovery phone
            </Button>
          </div>
          <div className="flex pt-4 items-center justify-between gap-4">
            <div className="space-y-1">
              <h4 className="text-sm font-medium">Backup codes</h4>
              <p className="text-sm text-muted-foreground">
                Generate backup codes to recover your account.
              </p>
            </div>
            <Button
              variant="ghost"
              onClick={() =>
                toast({
                  title: 'Recovery codes generated',
                })
              }
            >
              Generate codes
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default AccountRecoveryDetails;
