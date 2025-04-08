import { RequestHandler } from 'express';

const hiddenHandler: RequestHandler = (req, res) => {
  res.status(200).json({
    message: 'Hidden route accessed successfully',
    user: res.locals.session?.user,
  });
};

export default hiddenHandler;
