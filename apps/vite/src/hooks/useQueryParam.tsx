import { useLocation } from 'react-router-dom';

const useQueryParam = (key: string) => {
  const location = useLocation();

  return new URLSearchParams(location.search).get(key) || undefined;
};

export default useQueryParam;
