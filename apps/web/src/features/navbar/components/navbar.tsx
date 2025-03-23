import { cn } from '@/utils/tw';
import { Link } from 'react-router-dom';
import Profile from './profile';
import { buttonVariants } from '@/components/ui/button';
import Logo from '@/components/logo';
import { GitHubLogoIcon } from '@radix-ui/react-icons';

interface NavbarProps {
  variant: 'sticky' | 'fixed';
}

const Navbar = ({ variant }: NavbarProps) => {
  return (
    <nav
      className={cn(
        'top-0 left-0 right-0 z-50',
        variant === 'sticky' ? 'sticky' : 'fixed',
        'bg-background shadow-sm py-1 px-4',
      )}
    >
      <div className="container flex items-center gap-4 justify-between">
        <Link to="/">
          <Logo />
        </Link>
        <div className="flex items-center gap-4">
          <Link
            to="https://github.com/jindalujjwal0720/something"
            target="_blank"
            rel="noopener noreferrer"
            className={buttonVariants({ variant: 'outline' })}
          >
            <GitHubLogoIcon className="mr-2 h-4 w-4" />
            GitHub
          </Link>
          <Profile />
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
