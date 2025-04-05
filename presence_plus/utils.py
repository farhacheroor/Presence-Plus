# utils.py

from .models import LeaveBalance

def update_leave_balance_on_status_change(leave_request):
    leave_days = (leave_request.end_date - leave_request.start_date).days + 1
    balance = LeaveBalance.objects.filter(
        employee=leave_request.employee,
        leave_policy=leave_request.leave_policy
    ).first()

    if not balance:
        return  # Optionally: create a balance record here

    # Refund previously debited leave if status changes back
    if leave_request.status.lower() == "approved":
        if balance.total >= leave_days:
            balance.total -= leave_days
            balance.used += leave_days

    elif leave_request.status.lower() in ["rejected", "cancelled"]:
        balance.total += leave_days  # Refund
        balance.used -= leave_days if balance.used >= leave_days else balance.used

    balance.save()
