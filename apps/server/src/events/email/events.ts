export type EmailEventTypes = {
  'send-email': {
    to: string;
    subject: string;
    html?: string;
    text?: string;
  };
};
