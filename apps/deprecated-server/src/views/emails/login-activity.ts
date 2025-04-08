import { meta } from '../../config';
import { IDeviceInfo } from '../../types/middlewares/user-agent';

export const loginActivityEmailTemplate = (
  user: { name: string },
  loginDateTime: string,
  deviceInfo: IDeviceInfo,
) => {
  const subject = 'Login Activity Notification';
  const text = `Dear ${user.name},
  
  We noticed a login to your account from a new device. Here are the details of the recent login activity:
  
  Date and Time: ${loginDateTime}
  Browser: ${deviceInfo.browser}
  Platform: ${deviceInfo.platform}
  Operating System: ${deviceInfo.os}
  Source: ${deviceInfo.source}
  
  If this was not you or if you have any concerns, please contact our support team immediately. If you have any questions or need assistance, feel free to reach out to us.
  
  © ${meta.company.copyright.year} ${meta.company.name}. All rights reserved.
    `;

  return { html: '', text, subject };
};
