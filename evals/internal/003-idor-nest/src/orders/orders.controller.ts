import { Controller, Get, Param, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import type { AuthenticatedRequest } from '../auth/types';
import { OrdersService } from './orders.service';

@Controller('orders')
@UseGuards(JwtAuthGuard)
export class OrdersController {
  constructor(private readonly orders: OrdersService) {}

  @Get(':id')
  async findOne(@Param('id') id: string) {
    // Missing ownership check: any authenticated user can read any order.
    return this.orders.findById(id);
  }

  @Get()
  async mine(@Req() req: AuthenticatedRequest) {
    return this.orders.findByOwner(req.user.id);
  }
}
