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
    active_policies = LeavePolicy.objects.filter(status="active")

    for employee in Employee.objects.all():
        if not employee.hire_date:
            continue

        hire_date = employee.hire_date
        print(f"Processing employee {employee.id} hired on {hire_date}")

        for policy in active_policies:
            # Calculate number of full periods since hire date
            months_since_hire = (today.year - hire_date.year) * 12 + (today.month - hire_date.month)
            full_periods = months_since_hire // policy.frequency

            # Skip if no full periods have passed
            if full_periods < 1:
                continue

            # Calculate credit dates
            credit_dates = [
                hire_date + relativedelta(months=policy.frequency * i)
                for i in range(1, full_periods + 1)
                if (hire_date + relativedelta(months=policy.frequency * i)) <= today
            ]

            for credit_date in credit_dates:
                # Handle pro-rated first month
                if credit_date == hire_date + relativedelta(months=policy.frequency):
                    days_in_month = (credit_date - hire_date).days
                    prorate_factor = days_in_month / 30  # Adjust based on your needs
                    leave_to_credit = policy.amount * prorate_factor
                else:
                    leave_to_credit = policy.amount

                # Update leave balance
                balance, created = LeaveBalance.objects.update_or_create(
                    employee=employee,
                    leave_policy=policy,
                    defaults={
                        'total': (balance.total + leave_to_credit) if policy.carry_forward else leave_to_credit,
                        'used': 0
                    }
                )

                # Record transaction
                LeaveTransaction.objects.create(
                    employee=employee,
                    leave_policy=policy,
                    transaction_type="Credit",
                    date=credit_date,
                    credit=leave_to_credit,
                    debit=0,
                    pending=False
                )

    return "Leave credited successfully based on hire date."

