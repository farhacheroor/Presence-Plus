from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import *
from django.contrib.auth import get_user_model

User = get_user_model()

@receiver(post_save, sender=LeaveRequest)
def send_leave_request_notification(sender, instance, created, **kwargs):
    if created:
        # Notify HR when a leave request is created by employee
        hr_users = User.objects.filter(role__iexact="HR")
        for hr in hr_users:
            Notification.objects.create(
                user=hr,
                message=f"{instance.employee.user.username} has submitted a leave request.",
                type="Leave Request"
            )
    else:
        # Notify the employee when HR updates the leave request
        Notification.objects.create(
            user=instance.employee.user,
            message=f"Your leave request has been {instance.status}.",
            type="Leave Status"
        )

        # Notify all Admins that HR has updated a leave request
        admin_users = User.objects.filter(role__iexact="Admin")
        for admin in admin_users:
            Notification.objects.create(
                user=admin,
                message=f"HR has updated the leave request of {instance.employee.user.username} to {instance.status}.",
                type="Leave Request Update"
            )


def handle_leave_status_change(sender, instance, created, **kwargs):
    if not created:  # Trigger only on update, not on creation
        update_leave_balance_on_status_change(instance)

User = get_user_model()

@receiver(post_save, sender=LeaveRequest)
def update_leave_balance_on_status_change(sender, instance, created, **kwargs):
    if not created:
        previous = LeaveRequest.objects.get(pk=instance.pk)
        
        # If the previous status was "Approved" and now it's "Rejected" or "Pending"
        if previous.status == 'Pending' and instance.status in ['Rejected', 'Cancelled']:
            leave_balance = LeaveBalance.objects.filter(
                employee=instance.employee,
                leave_type=instance.leave_type
            ).first()
            if leave_balance:
                days = (instance.end_date - instance.start_date).days + 1
                leave_balance.used_leave = max(leave_balance.used_leave - days, 0)
                leave_balance.save()

        # If the previous status was not approved and now it's approved
        elif previous.status != 'Approved' and instance.status == 'Approved':
            leave_balance = LeaveBalance.objects.filter(
                employee=instance.employee,
                leave_type=instance.leave_type
            ).first()
            if leave_balance:
                days = (instance.end_date - instance.start_date).days + 1
                leave_balance.used_leave += days
                leave_balance.save()