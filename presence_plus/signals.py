from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import LeaveRequest, Notification
from django.contrib.auth import get_user_model

User = get_user_model()  # Get the User model dynamically

@receiver(post_save, sender=LeaveRequest)
def send_leave_request_notification(sender, instance, created, **kwargs):
    if created:
        # Notify HR when a leave request is created
        hr_users = User.objects.filter(role="HR")  # Adjust based on your model
        for hr in hr_users:
            Notification.objects.create(
                user=hr,
                message=f"{instance.employee.user.username} has submitted a leave request.",
                type="Leave Request"
            )
    else:
        # Notify Employee when HR updates the request
        Notification.objects.create(
            user=instance.employee.user,
            message=f"Your leave request has been {instance.status}.",
            type="Leave Status"
        )
