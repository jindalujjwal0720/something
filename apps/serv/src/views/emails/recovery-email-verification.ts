import { meta } from '../../config';

export const verifyRecoveryEmailTemplate = (
  recoveryEmailVerificationUrl: string,
  expiresIn: string,
) => {
  const subject = 'Verify Recovery Email';
  const text = `Dear,
  
  This email has been added as a recovery email to your another account. To complete this process and verify the email, please click the link below. This step is necessary to ensure the recovery email is correctly linked to your account. The link will expire in ${expiresIn}.
  
  Verify Recovery Email Link: ${recoveryEmailVerificationUrl}
  
  If you did not add a recovery email, please ignore this message. No changes will be made to any account.
  
  © ${meta.company.copyright.year} ${meta.company.name}. All rights reserved.
  `;

  return { html: '', text, subject };
};
