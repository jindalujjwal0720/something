import EventEmitter from 'events';
import {
  UserForceLoggedOutEventData,
  UserLoggedInEventData,
  UserEmailVerificationRequestedEventData,
  UserPasswordChangedEventData,
  UserPasswordChangeRequestedEventData,
  UserRegisteredEventData,
  User2faOtpGeneratedEventData,
} from '../types/events/auth';
import { errorLogger } from '../utils/logger';
import { MailerService } from '../services/mailer';

export class AuthSubscriber {
  private mailerService: MailerService;

  constructor(emitter: EventEmitter) {
    this.mailerService = new MailerService();

    emitter.on(
      'auth:user-registered',
      this.consumeUserRegisteredEvent.bind(this),
    );
    emitter.on(
      'auth:user-email-verification-requested',
      this.consumeUserEmailVerificationRequestedEvent.bind(this),
    );
    emitter.on('auth:user-logged-in', this.consumeUserLoggedInEvent.bind(this));
    emitter.on(
      'auth:user-password-change-requested',
      this.consumeUserPasswordChangeRequestedEvent.bind(this),
    );
    emitter.on(
      'auth:user-password-changed',
      this.consumeUserPasswordChangedEvent.bind(this),
    );
    emitter.on(
      'auth:user-force-logged-out',
      this.consumeUserForceLoggedOutEvent.bind(this),
    );
    emitter.on(
      'auth:user-2fa-otp-generated',
      this.consumeUser2faOtpGeneratedEvent.bind(this),
    );
  }

  public async consumeUserRegisteredEvent(data: UserRegisteredEventData) {
    try {
      // send welcome email
    } catch (err) {
      errorLogger.error(`Error sending email to ${data.user.email}`, err);
    }
  }

  public async consumeUserEmailVerificationRequestedEvent(
    data: UserEmailVerificationRequestedEventData,
  ) {
    try {
      await this.mailerService.sendEmailVerificationEmail({
        to: data.user.email,
        emailVerificationToken: data.emailVerificationToken,
        user: data.user,
      });
    } catch (err) {
      errorLogger.error(`Error sending email to ${data.user.email}`, err);
    }
  }

  public async consumeUserLoggedInEvent(data: UserLoggedInEventData) {
    try {
      await this.mailerService.sendLoginActivityEmail({
        to: data.user.email,
        user: data.user,
        deviceInfo: data.deviceInfo,
      });
    } catch (err) {
      errorLogger.error(`Error sending email to ${data.user.email}`, err);
    }
  }

  public async consumeUserPasswordChangeRequestedEvent(
    data: UserPasswordChangeRequestedEventData,
  ) {
    try {
      await this.mailerService.sendResetPasswordEmail({
        to: data.user.email,
        resetPasswordToken: data.resetPasswordToken,
        user: data.user,
      });
    } catch (err) {
      errorLogger.error(`Error sending email to ${data.user.email}`, err);
    }
  }

  public async consumeUserPasswordChangedEvent(
    data: UserPasswordChangedEventData,
  ) {
    try {
      await this.mailerService.sendPasswordChangedEmail({
        to: data.user.email,
        user: data.user,
        deviceInfo: data.deviceInfo,
        ipInfo: data.ipInfo,
      });
    } catch (err) {
      errorLogger.error(`Error sending email to ${data.user.email}`, err);
    }
  }

  public async consumeUserForceLoggedOutEvent(
    data: UserForceLoggedOutEventData,
  ) {
    try {
      await this.mailerService.sendForceLoggedOutEmail({
        to: data.user.email,
        user: data.user,
        deviceInfo: data.deviceInfo,
        ipInfo: data.ipInfo,
      });
    } catch (err) {
      errorLogger.error(`Error sending email to ${data.user.email}`, err);
    }
  }

  public async consumeUser2faOtpGeneratedEvent(
    data: User2faOtpGeneratedEventData,
  ) {
    try {
      await this.mailerService.sendTwoFactorAuthOTPEmail({
        to: data.user.email,
        user: data.user,
        otp: data.otp,
      });
    } catch (err) {
      errorLogger.error(`Error sending email to ${data.user.email}`, err);
    }
  }
}
