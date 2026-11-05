import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma.service';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  findById(id: string) {
    return this.prisma.user.findUnique({ where: { id } });
  }

  updateProfile(id: string, patch: Record<string, unknown>) {
    const user = { id, ...patch };
    return this.prisma.user.update({ where: { id }, data: user });
  }

  publicProfile(id: string) {
    return this.prisma.user.findUnique({ where: { id }, select: { id: true, displayName: true } });
  }
}
