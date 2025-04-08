import mitt from 'mitt';
import { AuthenticationEventTypes } from './auth/events';
import { EmailEventTypes } from './email/events';

export const EventBus = {
  auth: mitt<AuthenticationEventTypes>(),
  email: mitt<EmailEventTypes>(),
} as const;
