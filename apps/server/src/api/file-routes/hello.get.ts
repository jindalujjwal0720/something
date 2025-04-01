import { RequestHandler } from 'express';

const handler: RequestHandler = (req, res) => {
  res.json({
    message: 'Hello, World!',
  });
};

export default handler;
