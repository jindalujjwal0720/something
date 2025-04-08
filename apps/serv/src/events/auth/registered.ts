import { AuthenticationEvent } from './events';
import { EventBus } from '../bus';

EventBus.auth.on(AuthenticationEvent.REGISTERED, async (data) => {
  console.log('Send welcome email to', data.user.email);
});
