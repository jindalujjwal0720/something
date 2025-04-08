import path from 'path';
import { EventBus } from '../bus';
import { convertDurationToReadable } from '../../utils/time';
import { env } from '../../config';
import { AuthenticationEvent } from './events';
import { verifyRecoveryEmailTemplate } from '../../views/emails/recovery-email-verification';

EventBus.auth.on(
  AuthenticationEvent.RECOVERY_EMAIL_UPDATE_REQUESTED,
  async (data) => {
    const verificationLink =
      path.join(env.url, '/api/v1/auth/verify-email') +
      `?token=${data.emailVerificationToken}`;
    const template = verifyRecoveryEmailTemplate(
      verificationLink,
      convertDurationToReadable(data.tokenExpiresInSeconds),
    );
    EventBus.email.emit('send-email', {
      to: data.recoveryEmail,
      ...template,
    });
  },
);
