from flask import Blueprint, abort, g, jsonify, request

from .auth import login_required
from .models import Order, db

bp = Blueprint("orders", __name__)


@bp.post("/orders/<int:order_id>/pay")
@login_required
def pay(order_id: int):
    order = Order.query.filter_by(id=order_id, owner_id=g.user.id).first_or_404()
    if order.status != "NEW":
        abort(409)
    order.status = "PAID"
    db.session.commit()
    return jsonify(status=order.status)


# The shipping step never checks that the order was paid: calling it first ships an unpaid order.
@bp.post("/orders/<int:order_id>/ship")
@login_required
def ship(order_id: int):
    order = Order.query.filter_by(id=order_id, owner_id=g.user.id).first_or_404()
    order.status = "SHIPPED"
    order.shipping_address = request.json.get("address")
    db.session.commit()
    return jsonify(status=order.status)


@bp.post("/orders/<int:order_id>/cancel")
@login_required
def cancel(order_id: int):
    order = Order.query.filter_by(id=order_id, owner_id=g.user.id).first_or_404()
    if order.status not in ("NEW", "PAID"):
        abort(409)
    order.status = "CANCELLED"
    db.session.commit()
    return jsonify(status=order.status)
