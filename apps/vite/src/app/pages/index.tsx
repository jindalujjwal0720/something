import { Route, Routes } from 'react-router-dom';
import Settings from './settings';
import Auth from './auth';
import Home from './home';
import ProtectedRoute from '@/features/auth/components/protected-route';

const Pages = () => {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/settings/*" element={<ProtectedRoute />}>
        <Route path="*" element={<Settings />} />
      </Route>
      <Route path="/auth/*" element={<Auth />} />
    </Routes>
  );
};

export default Pages;
