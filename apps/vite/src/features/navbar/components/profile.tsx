import { Show } from '@/components/show';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Button, buttonVariants } from '@/components/ui/button';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import { useAuth } from '@/features/auth/components/auth-provider';
import { authClient } from '@/utils/auth-client';
import { Link } from 'react-router-dom';

const Profile = () => {
  const { session, isAuthenticated, isLoading: isUserLoading } = useAuth();

  const handleLogout = async () => {
    await authClient.signOut();
  };

  return (
    <>
      <Show when={!isAuthenticated && !isUserLoading}>
        <Link
          to="/auth/login"
          className={buttonVariants({ variant: 'default' })}
        >
          Login
        </Link>
      </Show>
      <Show when={isAuthenticated || isUserLoading}>
        <Popover>
          <PopoverTrigger asChild>
            {!isUserLoading ? (
              <div className="flex items-center gap-2 cursor-pointer hover:bg-muted rounded-md py-1.5 px-2">
                <Avatar className="size-7">
                  <AvatarImage
                    src={session?.user.image ?? ''}
                    alt={session?.user.name}
                  />
                  <AvatarFallback className="bg-muted-foreground text-background">
                    {session?.user.name[0]}
                  </AvatarFallback>
                </Avatar>
                <div>
                  <h4 className="text-sm font-semibold">
                    {session?.user.name}
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
            <div className="divide-y-2 flex flex-col gap-4">
              <div className="flex items-center gap-2 pb-4">
                <Avatar className="size-9">
                  <AvatarImage
                    src={session?.user.image ?? ''}
                    alt={session?.user.name}
                  />
                  <AvatarFallback className="bg-muted-foreground text-background">
                    {session?.user.name[0]}
                  </AvatarFallback>
                </Avatar>
                <div>
                  <h4 className="text-sm font-semibold">
                    {session?.user.name}
                  </h4>
                  <p className="text-xs text-muted-foreground">
                    {session?.user.email}
                  </p>
                </div>
              </div>
              <div>
                <div className="pb-4">
                  <Link
                    to="/settings"
                    className="block text-sm hover:text-blue-500"
                  >
                    Account Settings
                  </Link>
                </div>
              </div>
              <div className="pt-2">
                <Button
                  variant="ghost"
                  className="w-full"
                  onClick={handleLogout}
                >
                  Log out
                </Button>
              </div>
            </div>
          </PopoverContent>
        </Popover>
      </Show>
    </>
  );
};

export default Profile;
