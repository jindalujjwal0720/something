import { EventBus } from '../bus';
import { MailerService } from '../../services/mailer';
import { errorLogger } from '../../utils/logger';

const mailerService = new MailerService();

EventBus.email.on('send-email', async (data) => {
  try {
    await mailerService.sendEmail(data);
  } catch (err) {
    errorLogger.error(`Error sending email to ${data.to}`, err);
  }
});
