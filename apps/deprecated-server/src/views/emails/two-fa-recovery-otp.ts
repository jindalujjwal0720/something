import { meta } from '../../config';

export const twoFARecoveryOtpEmailTemplate = (
  user: { name: string },
  otp: string,
  expiresIn: string,
) => {
  const subject = '2FA OTP Sent to Recovery Email';
  const text = `Dear ${user.name},
  
  We received a request to log in using your account. As part of the 2FA authentication process, this One-Time Password (OTP) has been sent to your recovery email address.
  
  Please use the following OTP to complete the login process:
  
  OTP: ${otp}
  
  This OTP is valid for a single use and will expire in ${expiresIn}. If you did not request this login attempt, please disregard this email.
  
  Note: If you did not initiate this login attempt, someone might be trying to access your account. Please contact our support team immediately if you believe your account is at risk.
  
  © ${meta.company.copyright.year} ${meta.company.name}. All rights reserved.`;

  return { html: '', text, subject };
};
