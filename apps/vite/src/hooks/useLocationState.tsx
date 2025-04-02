import { useLocation } from 'react-router-dom';

const useLocationState = (key: string) => {
  const location = useLocation();

  return location.state?.[key];
};

export default useLocationState;
