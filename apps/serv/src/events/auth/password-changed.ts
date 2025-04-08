import { AuthenticationEvent } from './events';
import { EventBus } from '../bus';
import { passwordChangedEmailTemplate } from '../../views/emails/password-changed';

EventBus.auth.on(AuthenticationEvent.PASSWORD_CHANGED, async (data) => {
  const template = passwordChangedEmailTemplate(
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
