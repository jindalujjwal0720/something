import { meta } from '../../config';

export const emailVerificationTemplate = (
  user: { name: string },
  emailVerificationUrl: string,
  expiresIn: string,
) => {
  const subject = 'Email Verification';
  const text = `Dear ${user.name},
  
  Thank you for creating an account with us. To complete your registration, please verify your email address by clicking the link below. 
  
  Verification Link: ${emailVerificationUrl}
  
  This link will expire in ${expiresIn}.
  
  If you did not create an account, please ignore this email. No changes will be made to your email address.
  
  © ${meta.company.copyright.year} ${meta.company.name}. All rights reserved.
  `;

  return { html: '', text, subject };
};
