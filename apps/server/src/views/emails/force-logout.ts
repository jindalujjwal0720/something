import { meta } from '../../config';
import { IDeviceInfo, IUserIPInfo } from '../../types/middlewares/user-agent';

export const forceLogoutEmailTemplate = (
  user: { name: string },
  actionDateTime: string,
  ipInfo: IUserIPInfo,
  deviceInfo: IDeviceInfo,
) => {
  const subject = 'Security Alert: Force Logout Notification';
  const text = `Dear ${user.name},
  
  We have detected suspicious activity on your account, and as a precautionary measure, we have logged you out of all devices. This action was taken to protect your account from unauthorized access.
  
  Date and Time: ${actionDateTime}
  IP Address: ${ipInfo.ip}
  Location: ${ipInfo.location}
  Browser: ${deviceInfo.browser}
  Platform: ${deviceInfo.platform}
  Operating System: ${deviceInfo.os}
  Source: ${deviceInfo.source}
  
  If you recognize this activity, you can ignore this message. If you did not initiate this action or if you have any concerns about the security of your account, please contact our support team immediately.
  
  To regain access, please reset your password and review your recent login activity.
  
  © ${meta.company.copyright.year} ${meta.company.name}. All rights reserved.
    `;

  return { html: '', text, subject };
};
