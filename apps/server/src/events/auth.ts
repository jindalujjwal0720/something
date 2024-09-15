import EventEmitter from 'events';
import {
  UserForceLoggedOutEventData,
  UserLoggedInEventData,
  UserEmailVerificationRequestedEventData,
  UserPasswordChangedEventData,
  UserPasswordChangeRequestedEventData,
  UserRegisteredEventData,
  User2faOtpGeneratedEventData,
  User2FAEnabledEventData,
  User2FADisabledEventData,
  UserRecoveryEmailUpdateRequestedEventData,
  User2faRecoveryOtpGeneratedEventData,
} from '../types/events/auth';

export class AuthEventsPublisher {
  private emitter: EventEmitter;

  constructor(emitter: EventEmitter) {
    this.emitter = emitter;
  }

  public publishUserRegisteredEvent(data: UserRegisteredEventData) {
    this.emitter.emit('auth:user-registered', data);
  }

  public publishUserLoggedInEvent(data: UserLoggedInEventData) {
    this.emitter.emit('auth:user-logged-in', data);
  }

  public publishUserEmailVerificationRequestedEvent(
    data: UserEmailVerificationRequestedEventData,
  ) {
    this.emitter.emit('auth:user-email-verification-requested', data);
  }

  public publishUserForceLoggedOutEvent(data: UserForceLoggedOutEventData) {
    this.emitter.emit('auth:user-force-logged-out', data);
  }

  public publishUserPasswordChangeRequestedEvent(
    data: UserPasswordChangeRequestedEventData,
  ) {
    this.emitter.emit('auth:user-password-change-requested', data);
  }

  public publishUserPasswordChangedEvent(data: UserPasswordChangedEventData) {
    this.emitter.emit('auth:user-password-changed', data);
  }

  public publishUser2FAEnabledEvent(data: User2FAEnabledEventData) {
    this.emitter.emit('auth:user-2fa-enabled', data);
  }

  public publishUser2FADisabledEvent(data: User2FADisabledEventData) {
    this.emitter.emit('auth:user-2fa-disabled', data);
  }

  public publishUser2faOtpGeneratedEvent(data: User2faOtpGeneratedEventData) {
    this.emitter.emit('auth:user-2fa-otp-generated', data);
  }

  public publishUser2faRecoveryOtpGeneratedEvent(
    data: User2faRecoveryOtpGeneratedEventData,
  ) {
    this.emitter.emit('auth:user-2fa-recovery-otp-generated', data);
  }

  public publishUserRecoveryEmailUpdateRequestedEvent(
    data: UserRecoveryEmailUpdateRequestedEventData,
  ) {
    this.emitter.emit('auth:user-recovery-email-update-requested', data);
  }
}
