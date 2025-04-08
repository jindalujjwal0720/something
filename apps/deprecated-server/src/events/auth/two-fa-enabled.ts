import { AuthenticationEvent } from './events';
import { EventBus } from '../bus';
import { twoFAActivatedEmailTemplate } from '../../views/emails/two-fa-enabled';

EventBus.auth.on(AuthenticationEvent.TWO_FACTOR_AUTH_ENABLED, async (data) => {
  const template = twoFAActivatedEmailTemplate(
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
