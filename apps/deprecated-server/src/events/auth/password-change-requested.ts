import { AuthenticationEvent } from './events';
import { EventBus } from '../bus';
import { resetPasswordEmailTemplate } from '../../views/emails/reset-password';
import path from 'path';
import { env } from '../../config';
import { convertDurationToReadable } from '../../utils/time';

EventBus.auth.on(
  AuthenticationEvent.PASSWORD_CHANGE_REQUESTED,
  async (data) => {
    const passwordChangeLink =
      path.join(env.client.url, env.client.resetPasswordPath) +
      `?token=${data.resetPasswordToken}&email=${data.user.email}`;
    const template = resetPasswordEmailTemplate(
      data.user,
      passwordChangeLink,
      convertDurationToReadable(data.tokenExpiresInSeconds),
    );
    EventBus.email.emit('send-email', {
      to: data.user.email,
      ...template,
    });
  },
);
