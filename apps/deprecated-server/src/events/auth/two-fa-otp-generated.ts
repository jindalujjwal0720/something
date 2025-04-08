import { AuthenticationEvent } from './events';
import { EventBus } from '../bus';
import { twoFAOtpEmailTemplate } from '../../views/emails/two-fa-otp';
import { convertDurationToReadable } from '../../utils/time';

EventBus.auth.on(
  AuthenticationEvent.TWO_FACTOR_AUTH_OTP_GENERATED,
  async (data) => {
    const template = twoFAOtpEmailTemplate(
      data.user,
      data.otp,
      convertDurationToReadable(data.optExpiresInSeconds),
    );
    EventBus.email.emit('send-email', {
      to: data.user.email,
      ...template,
    });
  },
);
