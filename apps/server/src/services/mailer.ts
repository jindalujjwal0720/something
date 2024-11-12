import nodemailer from 'nodemailer';
import { Options } from 'nodemailer/lib/mailer';
import hbs from 'nodemailer-express-handlebars';
import { env, meta } from '../config';
import {
  LoginActivityEmailDTO,
  PasswordChangedEmailDTO,
  ResetPasswordEmailDTO,
  TwoFactorAuthOTPEmailDTO,
  EmailVerificationEmailDTO,
  TwoFactorAuthEnabledEmailDTO,
  TwoFactorAuthDisabledEmailDTO,
} from '../types/services/mailer';
import path from 'path';
import { errorLogger, logger } from '../utils/logger';
import { convertDurationToReadable } from '../utils/time';

type ExtendedOptions = Options & {
  template: string;
  context: Record<string, unknown>;
};

export class MailerService {
  private readonly transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      service: env.mail.service,
      host: env.mail.host,
      port: env.mail.port,
      secure: env.mail.secure,
      auth: {
        user: env.mail.auth.user,
        pass: env.mail.auth.pass,
      },
    });

    this.transporter.verify((error) => {
      if (error) {
        errorLogger.error('Mail server connection error', error);
      } else {
        logger.info('Mail server connected');
      }
    });

    // Set up Handlebars as the email template engine
    const handlebarOptions = {
      viewEngine: {
        extName: '.hbs',
        partialsDir: path.resolve(__dirname, '../views/emails/partials'),
        defaultLayout: '',
      },
      viewPath: path.resolve(__dirname, '../views/emails'),
      extName: '.hbs',
    };

    this.transporter.use('compile', hbs(handlebarOptions));
  }

  async sendEmailVerificationEmail({
    to,
    emailVerificationToken,
    user,
  }: EmailVerificationEmailDTO) {
    return this.transporter.sendMail({
      to,
      from: `${env.mail.auth.name} <${env.mail.auth.user}>`,
      subject: 'Email verification',
      template: 'email-verification',
      context: {
        user: {
          name: user.name,
        },
        email_verification_url: `${env.auth.emailVerificationUrl}?token=${emailVerificationToken}`,
        expires_in: convertDurationToReadable(
          env.auth.emailVerificationTokenExpiresInSeconds,
        ),
        company: {
          name: meta.company.name,
          logo_url: meta.company.logo,
          copyright_year: new Date().getFullYear(),
        },
      },
    } as ExtendedOptions);
  }

  async sendLoginActivityEmail({
    to,
    user,
    deviceInfo,
  }: LoginActivityEmailDTO) {
    return this.transporter.sendMail({
      to,
      from: `${env.mail.auth.name} <${env.mail.auth.user}>`,
      subject: 'A new login activity was detected',
      template: 'login-activity',
      context: {
        user: {
          name: user.name,
        },
        login_date_time: new Date().toLocaleString(),
        deviceInfo: deviceInfo,
        company: {
          name: meta.company.name,
          logo_url: meta.company.logo,
          copyright_year: new Date().getFullYear(),
        },
      },
    } as ExtendedOptions);
  }

  async sendResetPasswordEmail({
    to,
    user,
    resetPasswordToken,
  }: ResetPasswordEmailDTO) {
    return this.transporter.sendMail({
      to,
      from: `${env.mail.auth.name} <${env.mail.auth.user}>`,
      subject: 'Reset your password',
      template: 'reset-password',
      context: {
        user: {
          name: user.name,
        },
        reset_password_url: `${env.client.url}${env.client.resetPasswordPath}?token=${encodeURIComponent(resetPasswordToken)}&email=${encodeURIComponent(user.email || '')}`,
        expires_in: convertDurationToReadable(
          env.auth.resetPasswordTokenExpiresInSeconds,
        ),
        company: {
          name: meta.company.name,
          logo_url: meta.company.logo,
          copyright_year: new Date().getFullYear(),
        },
      },
    } as ExtendedOptions);
  }

  async sendPasswordChangedEmail({
    to,
    user,
    deviceInfo,
    ipInfo,
  }: PasswordChangedEmailDTO) {
    const location =
      Object.values(ipInfo.location)
        .filter((v) => v !== 'unknown')
        .join(', ') || 'unknown';

    return this.transporter.sendMail({
      to,
      from: `${env.mail.auth.name} <${env.mail.auth.user}>`,
      subject: 'Your password was changed',
      template: 'password-changed',
      context: {
        user: {
          name: user.name,
        },
        deviceInfo,
        ipInfo: {
          ip: ipInfo.ip,
          location,
        },
        change_date_time: new Date().toLocaleString(),
        company: {
          name: meta.company.name,
          logo_url: meta.company.logo,
          copyright_year: new Date().getFullYear(),
        },
      },
    } as ExtendedOptions);
  }

  async sendForceLoggedOutEmail({
    to,
    user,
    deviceInfo,
    ipInfo,
  }: PasswordChangedEmailDTO) {
    const location =
      Object.values(ipInfo.location)
        .filter((v) => v !== 'unknown')
        .join(', ') || 'unknown';

    return this.transporter.sendMail({
      to,
      from: `${env.mail.auth.name} <${env.mail.auth.user}>`,
      subject: 'You were logged out from all devices',
      template: 'force-logged-out',
      context: {
        user: {
          name: user.name,
        },
        deviceInfo,
        ipInfo: {
          ip: ipInfo.ip,
          location,
        },
        action_date_time: new Date().toLocaleString(),
        company: {
          name: meta.company.name,
          logo_url: meta.company.logo,
          copyright_year: new Date().getFullYear(),
        },
      },
    } as ExtendedOptions);
  }

  async send2FAEnabledEmail({
    to,
    user,
    deviceInfo,
    ipInfo,
  }: TwoFactorAuthEnabledEmailDTO) {
    const location =
      Object.values(ipInfo.location)
        .filter((v) => v !== 'unknown')
        .join(', ') || 'unknown';

    return this.transporter.sendMail({
      to,
      from: `${env.mail.auth.name} <${env.mail.auth.user}>`,
      subject: 'Two-factor authentication enabled',
      template: '2fa-enabled',
      context: {
        user: {
          name: user.name,
        },
        deviceInfo,
        ipInfo: {
          ip: ipInfo.ip,
          location,
        },
        action_date_time: new Date().toLocaleString(),
        company: {
          name: meta.company.name,
          logo_url: meta.company.logo,
          copyright_year: new Date().getFullYear(),
        },
      },
    } as ExtendedOptions);
  }

  async send2FADisabledEmail({
    to,
    user,
    deviceInfo,
    ipInfo,
  }: TwoFactorAuthDisabledEmailDTO) {
    const location =
      Object.values(ipInfo.location)
        .filter((v) => v !== 'unknown')
        .join(', ') || 'unknown';

    return this.transporter.sendMail({
      to,
      from: `${env.mail.auth.name} <${env.mail.auth.user}>`,
      subject: 'Two-factor authentication disabled',
      template: '2fa-disabled',
      context: {
        user: {
          name: user.name,
        },
        deviceInfo,
        ipInfo: {
          ip: ipInfo.ip,
          location,
        },
        action_date_time: new Date().toLocaleString(),
        company: {
          name: meta.company.name,
          logo_url: meta.company.logo,
          copyright_year: new Date().getFullYear(),
        },
      },
    } as ExtendedOptions);
  }

  async sendTwoFactorAuthOTPEmail({ to, otp, user }: TwoFactorAuthOTPEmailDTO) {
    return this.transporter.sendMail({
      to,
      from: `${env.mail.auth.name} <${env.mail.auth.user}>`,
      subject: 'One-time password for two-factor authentication',
      template: '2fa-otp',
      context: {
        user: {
          name: user.name,
        },
        otp,
        expires_in: convertDurationToReadable(
          env.twoFactorAuth.otp.expiresInSeconds,
        ),
        company: {
          name: meta.company.name,
          logo_url: meta.company.logo,
          copyright_year: new Date().getFullYear(),
        },
      },
    } as ExtendedOptions);
  }

  async sendRecoveryEmailOTP({ to, otp, user }: TwoFactorAuthOTPEmailDTO) {
    return this.transporter.sendMail({
      to,
      from: `${env.mail.auth.name} <${env.mail.auth.user}>`,
      subject: 'One-time password for account recovery',
      template: '2fa-recovery-otp',
      context: {
        user: {
          name: user.name,
        },
        otp,
        expires_in: convertDurationToReadable(
          env.twoFactorAuth.otp.expiresInSeconds,
        ),
        company: {
          name: meta.company.name,
          logo_url: meta.company.logo,
        },
      },
    } as ExtendedOptions);
  }

  async sendRecoveryEmailVerificationEmail({
    to,
    emailVerificationToken,
    user,
  }: EmailVerificationEmailDTO) {
    return this.transporter.sendMail({
      to,
      from: `${env.mail.auth.name} <${env.mail.auth.user}>`,
      subject: 'Email verification',
      template: 'recovery-email-verification',
      context: {
        user: {
          name: user.name,
        },
        recovery_email_verification_url: `${env.auth.recoveryEmailVerificationUrl}?token=${emailVerificationToken}`,
        expires_in: convertDurationToReadable(
          env.auth.emailVerificationTokenExpiresInSeconds,
        ),
        company: {
          name: meta.company.name,
          logo_url: meta.company.logo,
        },
      },
    } as ExtendedOptions);
  }
}
