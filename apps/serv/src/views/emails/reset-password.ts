import { meta } from '../../config';

export const resetPasswordEmailTemplate = (
  user: { name: string },
  resetPasswordUrl: string,
  expiresIn: string,
) => {
  const subject = 'Reset Your Password';
  const text = `Dear ${user.name},
  
  We received a request to reset the password for your account. To proceed, please click the link below to create a new password. The link will expire in ${expiresIn}.
  
  Reset Password Link: ${resetPasswordUrl}
  
  If you did not request this change, please ignore this email. Your password will remain unchanged.
  
  © ${meta.company.copyright.year} ${meta.company.name}. All rights reserved.
  `;

  return { html: '', text, subject };
};
