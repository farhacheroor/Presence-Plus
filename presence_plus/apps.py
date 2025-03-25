from django.apps import AppConfig
from django.db.models.signals import post_migrate
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model

def create_admin_user(sender, **kwargs):
    User = get_user_model()  # Get your custom user model
    try:
        if not User.objects.filter(username="admin").exists():
            user=User(
                username="farhacheroor1@gmail.com",
                email="farhacheroor1@gmail.com",
                password="admin123",  # Consider hashing the password
                role="admin"  # Set role if applicable in your model
            )
            user.set_password("admin123")  # Hash the password before saving
            user.save()
            print("Superuser 'admin' created successfully!")
    except ObjectDoesNotExist:
        pass

class YourAppConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "presence_plus"

    def ready(self):
        post_migrate.connect(create_admin_user, sender=self)
    def ready(self):
        import presence_plus.signals
