import nodemailer from 'nodemailer';
import { env } from '../config';
import { errorLogger, logger } from '../utils/logger';

export class MailerService {
  private readonly transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      service: env.mail.service,
      host: env.mail.host,
      port: env.mail.port,
      secure: env.mail.secure,
      auth: {
        user: env.mail.auth.user,
        pass: env.mail.auth.pass,
      },
    });

    this.transporter.verify((error) => {
      if (error) {
        errorLogger.error('Mail server connection error', error);
      } else {
        logger.info(`Mail server connected: ${env.mail.sender.email}`);
      }
    });
  }

  async sendEmail(options: {
    to: string;
    subject: string;
    html?: string;
    text?: string;
  }): Promise<void> {
    try {
      await this.transporter.sendMail({
        from: `${env.mail.sender.name} <${env.mail.sender.email}>`,
        to: options.to,
        subject: options.subject,
        html: options.html,
        text: options.text,
      });
    } catch (error) {
      errorLogger.error('Mail sending error', error);
    }
  }
}
