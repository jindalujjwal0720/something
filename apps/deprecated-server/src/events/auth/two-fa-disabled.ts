import { AuthenticationEvent } from './events';
import { EventBus } from '../bus';
import { twoFADisabledEmailTemplate } from '../../views/emails/two-fa-disabled';

EventBus.auth.on(AuthenticationEvent.TWO_FACTOR_AUTH_DISABLED, async (data) => {
  const template = twoFADisabledEmailTemplate(
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
