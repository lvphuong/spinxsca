import { Body, Controller, Get, Param, Patch, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import type { AuthenticatedRequest } from '../auth/types';
import { UsersService } from './users.service';

@Controller('users')
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get('me')
  async me(@Req() req: AuthenticatedRequest) {
    return this.users.findById(req.user.id);
  }

  // The whole body is bound to the entity: a caller can set `role`, `isAdmin` or `emailVerified`.
  @Patch('me')
  async updateMe(@Body() body: Record<string, unknown>, @Req() req: AuthenticatedRequest) {
    return this.users.updateProfile(req.user.id, body);
  }

  @Get(':id/public')
  async publicProfile(@Param('id') id: string) {
    return this.users.publicProfile(id);
  }
}
