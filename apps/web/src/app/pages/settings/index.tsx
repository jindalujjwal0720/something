import { Separator } from '@/components/ui/separator';
import SidebarNav from '@/features/settings/components/sidebar-nav';
import { Routes, Route } from 'react-router-dom';
import Account from './account';
import Security from './security';
import Preferences from './preferences';
import EnableTwoFactorAuthentication from './security/enable-2fa';
import SetupAuthenticator from './security/setup-authenticator';
import Navbar from '@/features/navbar/components/navbar';

const sidebarNavItems = [
  { href: '/settings', title: 'Account' },
  { href: '/settings/security', title: 'Security' },
  { href: '/settings/preferences', title: 'Preferences' },
];

const Settings = () => {
  return (
    <div className="pt-navbar">
      <Navbar variant="fixed" />
      <div className="space-y-6 p-6 pb-12 md:p-10 md:pb-16 md:block">
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
          <div className="flex-1 lg:max-w-3xl">
            <Routes>
              <Route path="" element={<Account />} />
              <Route path="/security">
                <Route path="" element={<Security />} />
                <Route path="2fa" element={<EnableTwoFactorAuthentication />} />
                <Route path="authenticator" element={<SetupAuthenticator />} />
              </Route>
              <Route path="/preferences" element={<Preferences />} />
            </Routes>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
