import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { db } from '../db';
import { env, meta } from '../config';
import { admin } from 'better-auth/plugins';
import { EventBus } from '../events/bus';
import { emailVerificationTemplate } from '../views/emails/email-verification';
import { convertDurationToReadable } from './time';
import { resetPasswordEmailTemplate } from '../views/emails/reset-password';
import * as authSchema from '../db/schema/auth';

export const auth = betterAuth({
  database: drizzleAdapter(db, {
    provider: 'pg',
    schema: {
      ...authSchema,
    },
  }),
  appName: meta.company.name,
  baseURL: `${env.url}/api/v1/auth`,
  trustedOrigins: [env.client.url],
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 8,
    requireEmailVerification: true,
    sendResetPassword: async ({ user, url }) => {
      const expiresIn = convertDurationToReadable(
        env.auth.resetPasswordTokenExpiresInSeconds,
      );
      const template = resetPasswordEmailTemplate(
        { name: user.name },
        url,
        expiresIn,
      );
      EventBus.email.emit('send-email', {
        to: user.email,
        subject: template.subject,
        html: template.html,
        text: template.text,
      });
    },
    resetPasswordTokenExpiresIn: env.auth.resetPasswordTokenExpiresInSeconds,
  },
  emailVerification: {
    sendVerificationEmail: async ({ user, url }) => {
      const expiresIn = convertDurationToReadable(
        env.auth.emailVerificationTokenExpiresInSeconds,
      );
      const template = emailVerificationTemplate(
        { name: user.name },
        url,
        expiresIn,
      );
      EventBus.email.emit('send-email', {
        to: user.email,
        subject: template.subject,
        html: template.html,
        text: template.text,
      });
    },
    sendOnSignUp: true,
    autoSignInAfterVerification: true,
    expiresIn: env.auth.emailVerificationTokenExpiresInSeconds,
  },
  plugins: [admin()],
});
