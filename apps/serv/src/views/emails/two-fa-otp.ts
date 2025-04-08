import { meta } from '../../config';

export const twoFAOtpEmailTemplate = (
  user: { name: string },
  otp: string,
  expiresIn: string,
) => {
  const subject = 'Your 2FA OTP Code';
  const text = `Dear ${user.name},
  
  We received a request to verify your identity. Please use the following One-Time Password (OTP) to complete the authentication process.
  
  OTP: ${otp}
  
  This OTP is valid for a single use and will expire in ${expiresIn}. If you did not request this authentication, please disregard this email.
  
  Note: If you received this email and did not request the authentication, someone might have obtained your password. Please reset your password or contact our support team immediately to secure your account.
  
  © ${meta.company.copyright.year} ${meta.company.name}. All rights reserved.
  `;

  return { html: '', text, subject };
};
