import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Button } from '@/components/ui/button';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import { useGetMeQuery, useLogoutMutation } from '@/features/auth/api/auth';
import {
  clearCredentials,
  selectIsAuthenticated,
  selectRole,
  setRole,
} from '@/features/auth/stores/auth';
import { getErrorMessage } from '@/utils/errors';
import { useDispatch, useSelector } from 'react-redux';
import { Link } from 'react-router-dom';
import { toast } from 'sonner';

const Profile = () => {
  const isAuthenticated = useSelector(selectIsAuthenticated);
  const { data: { user } = {}, isLoading: isUserLoading } = useGetMeQuery();
  const currentUserRole = useSelector(selectRole);
  const [logout] = useLogoutMutation();
  const dispatch = useDispatch();

  if (!isAuthenticated) {
    return null;
  }

  const handleLogout = async () => {
    try {
      await logout().unwrap();
      dispatch(clearCredentials());
    } catch (err) {
      toast.error(getErrorMessage(err));
    }
  };

  const handleViewAs = (role: string) => {
    dispatch(setRole(role));
  };

  return (
    <Popover>
      <PopoverTrigger asChild>
        {!isUserLoading ? (
          <div className="flex items-center gap-2 cursor-pointer hover:bg-muted rounded-md py-1.5 px-2">
            <Avatar className="size-7">
              <AvatarImage src={user?.imageUrl} alt={user?.name} />
              <AvatarFallback className="bg-muted-foreground text-background">
                {user?.name[0]}
              </AvatarFallback>
            </Avatar>
            <div>
              <h4 className="text-sm font-semibold">
                {user?.name}
                <span className="font-normal text-muted-foreground">
                  {' '}
                  ({currentUserRole})
                </span>
              </h4>
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-2 cursor-pointer hover:bg-muted rounded-md py-1.5 px-2 pointer-events-none">
            <Avatar className="size-7">
              <AvatarFallback className="bg-muted-foreground animate-pulse"></AvatarFallback>
            </Avatar>
            <span className="text-sm animate-pulse h-3 w-24 bg-muted-foreground rounded-lg"></span>
          </div>
        )}
      </PopoverTrigger>
      <PopoverContent>
        <div className="divide-y-2 space-y-4">
          <div className="flex items-center gap-2">
            <Avatar className="size-9">
              <AvatarImage src={user?.imageUrl} alt={user?.name} />
              <AvatarFallback className="bg-muted-foreground text-background">
                {user?.name[0]}
              </AvatarFallback>
            </Avatar>
            <div>
              <h4 className="text-sm font-semibold">{user?.name}</h4>
              <p className="text-xs text-muted-foreground">{user?.email}</p>
            </div>
          </div>
          <div>
            {user?.roles && user.roles.length > 1 && (
              <div className="pt-4 space-y-4">
                {user?.roles
                  .filter((role) => role !== currentUserRole)
                  .map((role) => (
                    <div
                      key={role}
                      className="text-sm cursor-pointer hover:text-blue-500"
                      onClick={() => handleViewAs(role)}
                    >
                      View as {role}
                    </div>
                  ))}
              </div>
            )}
            <div className="pt-4">
              <Link
                to="/settings"
                className="block text-sm hover:text-blue-500"
              >
                Account Settings
              </Link>
            </div>
          </div>
          <div className="pt-2">
            <Button variant="ghost" className="w-full" onClick={handleLogout}>
              Log out
            </Button>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
};

export default Profile;
