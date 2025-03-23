# tasks.py
from celery import shared_task
from presence_plus.models import *
from datetime import datetime, timezone


@shared_task
def update_leave_status():
    """
    Automatically update leave status (e.g., approved, rejected) in the background.
    """
    leave_requests = LeaveRequest.objects.filter(status="pending")
    for leave in leave_requests:
        # Update leave status based on logic, e.g., if expired, mark as rejected
        if leave.date < datetime.now().date():
            leave.status = "rejected"
            leave.save()


@shared_task
def update_attendance():
    """
    Automatically update attendance records (e.g., mark absent if not clocked in).
    """
    today = datetime.now().date()
    employees = Attendance.objects.filter(date=today, status="not_clocked")

    for employee in employees:
        # Mark them as absent if not clocked in by a certain time
        employee.status = "absent"
        employee.save()

@shared_task
def credit_leave():
    today = timezone.now().date()
    employees = Employee.objects.all()
    active_policies = LeavePolicy.objects.filter(status="active")

    for policy in active_policies:
        leave_to_credit = 0  # Default to 0 unless a condition is met

        if policy.frequency == 6:  # Special Leave (credited every 6 months, amount=1)
            if today.month in [1, 7]:  # Only credit in January and July
                leave_to_credit = 1
        else:  # Other leaves based on frequency (e.g., monthly, quarterly)
            if today.month % policy.frequency == 0:
                leave_to_credit = policy.amount * policy.frequency

        if leave_to_credit > 0:  # Proceed only if leave is credited
            for employee in employees:
                leave_balance, created = LeaveBalance.objects.get_or_create(
                    employee=employee,
                    leave_policy=policy,
                    defaults={"total": 0, "used": 0},
                )

                # Handle carry forward logic
                if policy.carry_forward:
                    new_total = leave_balance.total + leave_to_credit
                else:
                    if today.month == 1:  # Reset balance in January if carry_forward=False
                        new_total = leave_to_credit
                    else:
                        new_total = leave_to_credit  # Overwrite total without adding

                # Update leave balance
                leave_balance.total = new_total
                leave_balance.save()

                # Create a transaction record
                LeaveTransaction.objects.create(
                    employee=employee,
                    leave_policy=policy,
                    transaction_type="Credit",
                    date=today,
                    credit=leave_to_credit
                )

    return "Leave credited based on policy frequency and amount, including annual and special leave."