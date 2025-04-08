import path from 'path';
import { EventBus } from '../bus';
import { convertDurationToReadable } from '../../utils/time';
import { emailVerificationTemplate } from '../../views/emails/email-verification';
import { env } from '../../config';
import { AuthenticationEvent } from './events';

EventBus.auth.on(
  AuthenticationEvent.EMAIL_VERIFICATION_REQUESTED,
  async (data) => {
    const verificationLink =
      path.join(env.url, '/api/v1/auth/verify-email') +
      `?token=${data.emailVerificationToken}`;
    const template = emailVerificationTemplate(
      data.user,
      verificationLink,
      convertDurationToReadable(data.tokenExpiresInSeconds),
    );
    EventBus.email.emit('send-email', {
      to: data.user.email,
      ...template,
    });
  },
);
