# tasks.py
from datetime import datetime
from celery import shared_task
from presence_plus.models import *
#from datetime import datetime, timezone
from django.utils import timezone

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
    print("Executing credit_leave task")
    today = timezone.now().date()
    employees = Employee.objects.all()
    active_policies = LeavePolicy.objects.filter(status="active")

    for policy in active_policies:
        leave_to_credit = 0

        if policy.frequency == 6 and today.month in [1, 7]:  
            leave_to_credit = 1
        elif today.month % policy.frequency == 0:
            leave_to_credit = policy.amount * policy.frequency

        for employee in employees:
            # Get or create leave balance for the employee
            leave_balance, created = LeaveBalance.objects.get_or_create(
                employee=employee,
                leave_policy=policy,
                defaults={"total": 0, "used": 0},
            )

            # Credit Leave Logic
            if leave_to_credit > 0:
                if policy.carry_forward:
                    new_total = leave_balance.total + leave_to_credit
                else:
                    new_total = leave_to_credit if today.month == 1 else leave_to_credit

                leave_balance.total = new_total
                leave_balance.save()

                # Create a LeaveTransaction for crediting
                LeaveTransaction.objects.create(
                    employee=employee,
                    leave_policy=policy,
                    transaction_type="Credit",
                    date=today,
                    credit=leave_to_credit,
                    debit=0,
                    pending=False
                )

            # **Debit Leave Logic: If employee has pending leave requests**
            pending_leaves = LeaveRequest.objects.filter(employee=employee, status="approved")

            for leave in pending_leaves:
                if leave.days <= leave_balance.total:
                    leave_balance.total -= leave.days
                    leave_balance.used += leave.days
                    leave_balance.save()

                    # Create a LeaveTransaction for debiting
                    LeaveTransaction.objects.create(
                        employee=employee,
                        leave_policy=policy,
                        transaction_type="Debit",
                        date=today,
                        credit=0,
                        debit=leave.days,
                        pending=False
                    )

    return "Leave credited & debited successfully."

