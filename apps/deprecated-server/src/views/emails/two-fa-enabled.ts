import { meta } from '../../config';
import { IDeviceInfo, IUserIPInfo } from '../../types/middlewares/user-agent';

export const twoFAActivatedEmailTemplate = (
  user: { name: string },
  actionDateTime: string,
  ipInfo: IUserIPInfo,
  deviceInfo: IDeviceInfo,
) => {
  const subject = 'Security Alert: 2FA Activated Notification';
  const text = `Dear ${user.name},
  
  We wanted to let you know that Two-Factor Authentication (2FA) has been successfully activated on your account. For your security, we have set up email-based One-Time Passwords (OTPs) as the default 2FA method.
  
  Email-based OTPs will be sent to your registered email address when required, adding an extra layer of protection to your account.
  
  Date and Time: ${actionDateTime}
  IP Address: ${ipInfo.ip}
  Location: ${ipInfo.location}
  Browser: ${deviceInfo.browser}
  Platform: ${deviceInfo.platform}
  Operating System: ${deviceInfo.os}
  Source: ${deviceInfo.source}
  
  Additionally, you can use an authenticator app to further enhance your account security. Authenticator apps generate time-based OTPs that can be used in conjunction with email-based OTPs.
  
  If you did not initiate this activation or if you have any concerns, please contact our support team immediately. For any questions or further assistance, feel free to reach out to us.
  
  © ${meta.company.copyright.year} ${meta.company.name}. All rights reserved.
    `;

  return { html: '', text, subject };
};
