import { AuthenticationEvent } from './events';
import { EventBus } from '../bus';
import { convertDurationToReadable } from '../../utils/time';
import { twoFARecoveryOtpEmailTemplate } from '../../views/emails/two-fa-recovery-otp';

EventBus.auth.on(
  AuthenticationEvent.TWO_FACTOR_AUTH_RECOVERY_OTP_GENERATED,
  async (data) => {
    const template = twoFARecoveryOtpEmailTemplate(
      data.user,
      data.otp,
      convertDurationToReadable(data.optExpiresInSeconds),
    );
    EventBus.email.emit('send-email', {
      to: data.recoveryEmail,
      ...template,
    });
  },
);
