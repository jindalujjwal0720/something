import { BrowserRouter } from 'react-router-dom';

export interface RouterProps {
  children: React.ReactNode;
}

const Router = ({ children }: RouterProps) => {
  return <BrowserRouter>{children}</BrowserRouter>;
};

export default Router;
