import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma.service';

@Injectable()
export class OrdersService {
  constructor(private readonly prisma: PrismaService) {}

  findForOwner(id: string, ownerId: string) {
    return this.prisma.order.findFirst({ where: { id, ownerId } });
  }

  updateForOwner(id: string, ownerId: string, note: string) {
    return this.prisma.order.updateMany({ where: { id, ownerId }, data: { note } });
  }

  removeForOwner(id: string, ownerId: string) {
    return this.prisma.order.deleteMany({ where: { id, ownerId } });
  }

  findByOwner(ownerId: string) {
    return this.prisma.order.findMany({ where: { ownerId } });
  }
}
