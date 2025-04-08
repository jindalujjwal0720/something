import { meta } from '../../config';
import { IDeviceInfo, IUserIPInfo } from '../../types/middlewares/user-agent';

export const twoFADisabledEmailTemplate = (
  user: { name: string },
  actionDateTime: string,
  ipInfo: IUserIPInfo,
  deviceInfo: IDeviceInfo,
) => {
  const subject = 'Security Alert: 2FA Disabled Notification';
  const text = `Dear ${user.name},
  
  This is to inform you that Two-Factor Authentication (2FA) has been disabled on your account.
  
  2FA is a critical security feature designed to protect your account from unauthorized access. If this change was not requested by you or if you have any concerns, please take immediate action.
  
  Date and Time: ${actionDateTime}
  IP Address: ${ipInfo.ip}
  Location: ${ipInfo.location}
  Browser: ${deviceInfo.browser}
  Platform: ${deviceInfo.platform}
  Operating System: ${deviceInfo.os}
  Source: ${deviceInfo.source}
  
  If you have any concerns or questions, or if you did not authorize this change, please contact our support team immediately.
  
  © ${meta.company.copyright.year} ${meta.company.name}. All rights reserved.
    `;

  return { html: '', text, subject };
};
