import { Button } from '@/components/ui/button';
import { CopyIcon, DownloadIcon } from '@radix-ui/react-icons';
import { toast } from 'sonner';

const RecoveryCodes = ({ recoveryCodes }: { recoveryCodes: string[] }) => {
  const handleDownloadAll = () => {
    const element = document.createElement('a');
    const file = new Blob([recoveryCodes.join('\n')], {
      type: 'text/plain',
    });
    element.href = URL.createObjectURL(file);
    element.download = 'recovery-codes.txt';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const handleCopyAll = () => {
    navigator.clipboard.writeText(recoveryCodes.join('\n'));
    toast.success('Recovery codes copied to clipboard.');
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-2">
        <h3 className="font-medium">Recovery codes</h3>
        <p className="text-sm text-muted-foreground">
          <span className="font-semibold">
            These recovery codes are one-time use only and cannot be retrieved
            later.
          </span>{' '}
          Save these recovery codes in a safe place. You can use these codes to
          access your account if you lose access to your two-factor
          authentication device.
        </p>
      </div>
      <ul className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {recoveryCodes.map((code, index) => (
          <li
            key={index}
            className="bg-gray-100 py-2 px-4 rounded-md text-center gap-2"
          >
            <span>{code.substring(0, 4)}</span>
            <span>{code.substring(4)}</span>
          </li>
        ))}
      </ul>
      <div className="flex gap-4">
        <Button
          onClick={handleDownloadAll}
          variant="outline"
          className="flex gap-2 items-center"
        >
          <DownloadIcon />
          <span>Download</span>
        </Button>
        <Button
          onClick={handleCopyAll}
          variant="outline"
          className="flex gap-2"
        >
          <CopyIcon />
          <span>Copy</span>
        </Button>
      </div>
    </div>
  );
};

export default RecoveryCodes;
