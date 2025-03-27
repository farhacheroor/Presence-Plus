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

    for employee in employees:
        hire_date = employee.hire_date
        if not hire_date:
            continue  # Skip if hire_date is not set

        # Get total months since the employee's hire date
        total_months_since_hire = (today.year - hire_date.year) * 12 + (today.month - hire_date.month)

        # Start iterating from the month of hire_date to today
        for month_offset in range(total_months_since_hire + 1):
            crediting_date = hire_date + timedelta(days=month_offset * 30)  # Approximate month offset
            if crediting_date > today:
                break  # Stop when reaching today's date

            for policy in active_policies:
                leave_to_credit = 0

                # Check if this month should credit leave based on policy frequency
                if policy.frequency == 6 and crediting_date.month in [1, 7]:  
                    leave_to_credit = 1
                elif crediting_date.month % policy.frequency == 0:
                    leave_to_credit = policy.amount * policy.frequency

                # Get or create leave balance for the employee
                leave_balance, created = LeaveBalance.objects.get_or_create(
                    employee=employee,
                    leave_policy=policy,
                    defaults={"total": 0, "used": 0},
                )

                # Credit leave if applicable
                if leave_to_credit > 0:
                    if policy.carry_forward:
                        leave_balance.total += leave_to_credit
                    else:
                        leave_balance.total = leave_to_credit if crediting_date.month == hire_date.month else leave_to_credit

                    leave_balance.save()

                    # Create a LeaveTransaction for crediting
                    LeaveTransaction.objects.create(
                        employee=employee,
                        leave_policy=policy,
                        transaction_type="Credit",
                        date=crediting_date,
                        credit=leave_to_credit,
                        debit=0,
                        pending=False
                    )

    return "Leave credited successfully based on hire date."

