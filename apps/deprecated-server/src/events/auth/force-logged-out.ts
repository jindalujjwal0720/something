import { AuthenticationEvent } from './events';
import { EventBus } from '../bus';
import { forceLogoutEmailTemplate } from '../../views/emails/force-logout';

EventBus.auth.on(AuthenticationEvent.FORCE_LOGGED_OUT, async (data) => {
  const template = forceLogoutEmailTemplate(
    data.user,
    Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    }).format(new Date()),
    data.ipInfo,
    data.deviceInfo,
  );
  EventBus.email.emit('send-email', {
    to: data.user.email,
    ...template,
  });
});
