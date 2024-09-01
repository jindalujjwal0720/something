import * as e from 'express';
import User from '../../models/user';
import { UserService } from '../../services/user';

export class UserController {
  private userService: UserService;

  constructor() {
    this.userService = new UserService(User);
  }

  public async getMe(req: e.Request, res: e.Response, next: e.NextFunction) {
    try {
      const { email } = req.user;

      const user = await this.userService.findUserByEmail(email);

      res.status(200).json({ user });
    } catch (err) {
      next(err);
    }
  }
}
