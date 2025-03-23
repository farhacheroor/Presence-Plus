from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    role = models.CharField(max_length=100)
    department = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)

class Community(models.Model):
    community_name = models.CharField(max_length=100)

class Designation(models.Model):
    desig_name = models.CharField(max_length=100)

class Employee(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    hire_date = models.DateField()
    emp_num = models.CharField(max_length=50, unique=True)
    image = models.ImageField(upload_to='employees/', null=True, blank=True)
    status = models.CharField(max_length=50)
    priority = models.CharField(max_length=255, null=True, blank=True)
    community= models.ForeignKey(Community, on_delete=models.CASCADE,  null=True, blank=True)
    designation= models.ForeignKey(Designation, on_delete=models.CASCADE,  null=True, blank=True)

class Attendance(models.Model):
    STATUS_CHOICES = [
        ('present', 'Present'),
        ('absent', 'Absent'),
        ('late', 'Late')
    ]
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    date = models.DateField()
    check_in = models.TimeField()
    check_out = models.TimeField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='absent')
    
class AttendanceRequest(models.Model):
    STATUS_CHOICES = [('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')]

    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    date = models.DateField()
    check_in = models.TimeField()
    check_out = models.TimeField()
    work_type = models.CharField(max_length=20, blank=True, null=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    image = models.ImageField(upload_to='attendance/', null=True, blank=True)

class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.TextField()
    time_stamp = models.DateTimeField(auto_now_add=True)
    type = models.CharField(max_length=50)

class WorkingHours(models.Model):
    shift_type = models.CharField(max_length=50)
    start_time = models.TimeField()
    end_time = models.TimeField()
    status = models.CharField(max_length=20, choices=[('active', 'Active'), ('inactive', 'Inactive')])

class ShiftRoster(models.Model):
    start_date = models.DateField()
    end_date = models.DateField()
    working_hours = models.ForeignKey(WorkingHours, on_delete=models.CASCADE)

class Overtime(models.Model):
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    date = models.DateField()
    hours = models.IntegerField()
    reason = models.TextField()
    status = models.CharField(max_length=10, choices=[('upcoming', 'Upcoming'), ('missed', 'Missed'), ('completed', 'Completed')], default='upcoming')

class EmployeeShiftAssignment(models.Model):
    date = models.DateField()
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    shift_roster = models.ForeignKey(ShiftRoster, on_delete=models.CASCADE)
    shift = models.ForeignKey(WorkingHours, on_delete=models.CASCADE)

class LeavePolicy(models.Model):
    leave_type = models.CharField(max_length=50)
    carry_forward = models.BooleanField()
    amount = models.IntegerField()
    frequency = models.IntegerField()
    status = models.CharField(max_length=20, choices=[('active', 'Active'), ('inactive', 'Inactive')])


class LeaveRequest(models.Model):
    STATUS_CHOICES = [('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')]
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    start_date = models.DateField()
    end_date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    cancellation_request = models.BooleanField(default=False)
    reason = models.TextField()
    cancellation_reason = models.TextField(null= True, blank=True)
    reject_reason = models.TextField(null= True, blank=True)
    leave_policy= models.ForeignKey(LeavePolicy, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='leaverequest/', null=True, blank=True)

class LeaveTransaction(models.Model):
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    transaction_type = models.CharField(max_length=50)
    date = models.DateField()
    credit = models.IntegerField(default=0)
    debit = models.IntegerField(default=0)
    pending = models.BooleanField(default=False)
    leave_policy= models.ForeignKey(LeavePolicy, on_delete=models.CASCADE)

class LeaveBalance(models.Model):
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    used = models.IntegerField()
    total = models.IntegerField()
    last_updated = models.DateField(auto_now=True)
    leave_policy = models.ForeignKey(LeavePolicy, on_delete=models.CASCADE)
    leave_transaction = models.ForeignKey(LeaveTransaction, on_delete=models.CASCADE)

class LeaveType(models.Model):
    leave = models.CharField(max_length=100)

class PublicHoliday(models.Model):
    name = models.CharField(max_length=100)
    date = models.DateField()
    leavetype = models.ForeignKey(LeaveType, on_delete=models.CASCADE, null=True, blank=True)
    status = models.CharField(max_length=20, choices=[('active', 'Active'), ('inactive', 'Inactive')])
    community = models.ForeignKey(Community, on_delete=models.CASCADE, null=True, blank=True)

