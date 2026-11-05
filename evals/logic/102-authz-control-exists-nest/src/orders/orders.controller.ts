import { Body, Controller, Delete, Get, Param, Put, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { OwnershipGuard } from '../auth/ownership.guard';
import type { AuthenticatedRequest } from '../auth/types';
import { OrdersService } from './orders.service';

@Controller('orders')
@UseGuards(JwtAuthGuard)
export class OrdersController {
  constructor(private readonly orders: OrdersService) {}

  @Get(':id')
  @UseGuards(OwnershipGuard)
  async findOne(@Param('id') id: string, @Req() req: AuthenticatedRequest) {
    return this.orders.findForOwner(id, req.user.id);
  }

  @Put(':id')
  @UseGuards(OwnershipGuard)
  async update(@Param('id') id: string, @Body() body: { note: string }, @Req() req: AuthenticatedRequest) {
    return this.orders.updateForOwner(id, req.user.id, body.note);
  }

  @Delete(':id')
  @UseGuards(OwnershipGuard)
  async remove(@Param('id') id: string, @Req() req: AuthenticatedRequest) {
    return this.orders.removeForOwner(id, req.user.id);
  }

  @Get()
  async mine(@Req() req: AuthenticatedRequest) {
    return this.orders.findByOwner(req.user.id);
  }
}
