import { cn } from '@/utils/tw';
import { Link } from 'react-router-dom';
import Profile from './profile';
import { buttonVariants } from '@/components/ui/button';
import { useSelector } from 'react-redux';
import { selectIsAuthenticated } from '@/features/auth/stores/auth';

interface NavbarProps {
  variant: 'sticky' | 'fixed';
}

const Navbar = ({ variant }: NavbarProps) => {
  const isAuthenticated = useSelector(selectIsAuthenticated);

  return (
    <nav
      className={cn(
        'top-0 left-0 right-0 z-50',
        variant === 'sticky' ? 'sticky' : 'fixed',
        'bg-white shadow-sm py-1 px-4',
      )}
    >
      <div className="container flex items-center gap-4 justify-between">
        <div className="">
          <Link to="/" className="">
            <h1 className="font-semibold">Something</h1>
          </Link>
        </div>
        <div className="flex items-center gap-2">
          {!isAuthenticated && (
            <Link
              to="/auth/login"
              className={buttonVariants({ variant: 'ghost' })}
            >
              Login
            </Link>
          )}
          <Profile />
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
