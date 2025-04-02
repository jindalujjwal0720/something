import { PropsWithChildren } from 'react';

export const Show = ({ when, children }: PropsWithChildren<{ when: any }>) => {
  return <>{!!when && children}</>;
};
