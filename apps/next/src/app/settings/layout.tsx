import { Separator } from '@/components/ui/separator';
import SidebarNav from '@/features/settings/components/sidebar-nav';
import Navbar from '@/features/navbar/components/navbar';
import { PropsWithChildren } from 'react';

const sidebarNavItems = [
  { href: '/settings', title: 'Account' },
  { href: '/settings/security', title: 'Security' },
  { href: '/settings/preferences', title: 'Preferences' },
];

const SettingsLayout = ({ children }: PropsWithChildren) => {
  return (
    <div className="pt-navbar">
      <Navbar variant="fixed" />
      <div className="space-y-6 pt-5 px-6 pb-12 md:px-10 md:pb-16 md:block">
        <div className="space-y-0.5">
          <h2 className="text-2xl font-bold tracking-tight">Settings</h2>
          <p className="text-muted-foreground">
            Manage your account settings and set preferences.
          </p>
        </div>
        <Separator className="my-6" />
        <div className="flex flex-col space-y-8 lg:flex-row lg:space-x-12 lg:space-y-0">
          <aside className="lg:w-1/5">
            <SidebarNav items={sidebarNavItems} />
          </aside>
          <div className="flex-1 lg:max-w-3xl">{children}</div>
        </div>
      </div>
    </div>
  );
};

export default SettingsLayout;
