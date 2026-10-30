import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma.service';

@Injectable()
export class OrdersService {
  constructor(private readonly prisma: PrismaService) {}

  findById(id: string) {
    return this.prisma.order.findUnique({ where: { id } });
  }

  findByOwner(ownerId: string) {
    return this.prisma.order.findMany({ where: { ownerId } });
  }
}
