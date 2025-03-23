import { meta } from '../../config';
import { IDeviceInfo, IUserIPInfo } from '../../types/middlewares/user-agent';

export const passwordChangedEmailTemplate = (
  user: { name: string },
  changeDateTime: string,
  ipInfo: IUserIPInfo,
  deviceInfo: IDeviceInfo,
) => {
  const subject = 'Password Changed Notification';
  const text = `Dear ${user.name},
  
  Your password has been successfully changed. If you made this change, you can ignore this email. If you did not make this change, please contact our support team immediately as your account may have been compromised.
  
  Date and Time: ${changeDateTime}
  IP Address: ${ipInfo.ip}
  Location: ${[ipInfo.location.city, ipInfo.location.state, ipInfo.location.country].filter(Boolean).join(', ')}
  Browser: ${deviceInfo.browser}
  Platform: ${deviceInfo.platform}
  Operating System: ${deviceInfo.os}
  Source: ${deviceInfo.source}
  
  If you have any questions or need further assistance, feel free to reach out to our support team.
  
  © ${meta.company.copyright.year} ${meta.company.name}. All rights reserved.
    `;

  return { html: '', text, subject };
};
