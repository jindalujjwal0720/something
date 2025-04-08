import { AuthenticationEvent } from './events';
import { EventBus } from '../bus';

EventBus.auth.on(AuthenticationEvent.LOGGED_IN, async (data) => {
  console.log('User logged in', data.user.email);
});
