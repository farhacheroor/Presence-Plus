import logging
import random
import string
from django.core.mail import send_mail
from django.db.models import Count, Sum
from django.utils.timezone import now
from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from presence_plus.models import *
from django.contrib.auth import get_user_model
from django.utils.crypto import get_random_string
from django.db import IntegrityError, transaction


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password', 'role', 'department']

    def create(self, validated_data):
        validated_data["password"] = make_password(validated_data["password"])  # Hash password
        return super().create(validated_data)

class LeaveRequestSerializer(serializers.ModelSerializer):
    employee_name = serializers.CharField(source="employee.name", read_only=True)
    leave_type = serializers.CharField(source="leave_policy.leave_type", read_only=True)  # Fetch from LeavePolicy

    class Meta:
        model = LeaveRequest
        fields = ["id", "employee_name", "start_date", "end_date", "reason", "status", "leave_type", "cancellation_reason"]

class LeaveRequestHistorySerializer(serializers.ModelSerializer):
    employee_name = serializers.CharField(source="employee.name", read_only=True)
    leave_type = serializers.CharField(source="leave_policy.leave_type", read_only=True)
    class Meta:
        model = LeaveRequest
        fields = ["employee_name", "start_date", "end_date", "reason", "leave_type", "status"]  # Make sure all fields are included
        # OR explicitly list the fields you want

class LeavePolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = LeavePolicy
        fields = "__all__"
        read_only_fields = ["status"]  # Prevents frontend from modifying status

    def validate_amount(self, value):
        """Ensure that leave amount is positive"""
        if value <= 0:
            raise serializers.ValidationError("Leave amount must be greater than zero.")
        return value

    def validate_carry_forward(self, value):
        """
        Allow frontend to send carry_forward as:
        - Boolean (`true`/`false`)
        - String (`"yes"`/`"no"`)
        """
        if isinstance(value, str):
            value = value.lower()
            if value == "yes":
                return True
            elif value == "no":
                return False
            else:
                raise serializers.ValidationError("carry_forward must be 'yes' or 'no'.")
        elif isinstance(value, bool):
            return value
        else:
            raise serializers.ValidationError("Invalid carry_forward value.")

        return value

    def create(self, validated_data):
        """Automatically set status to 'active' when creating a new leave policy"""
        validated_data["status"] = "active"
        return super().create(validated_data)

    def delete(self, instance):
        """Instead of deleting, update the status to 'inactive'"""
        instance.status = "inactive"
        instance.save()
        return instance

class WorkTimePolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkingHours
        fields = "__all__"

    def validate_status(self, value):
        # ✅ Get choices from model field
        valid_choices = [choice[0] for choice in WorkingHours._meta.get_field("status").choices]
        
        value = value.lower()  # ✅ Convert input to lowercase
        if value not in valid_choices:
            raise serializers.ValidationError(f"'{value}' is not a valid choice. Choose from {valid_choices}.")
        
        return value  # ✅ Return normalized value

class PublicHolidaySerializer(serializers.ModelSerializer):
    class Meta:
        model = PublicHoliday
        fields = '__all__'

    def validate(self, data):
        """Ensure community is only set for community-based holidays"""
        leave_type = data.get("leave_type")
        community = data.get("community")

        if leave_type and leave_type.leave.lower() == "public" and community is not None:
            raise serializers.ValidationError("Public holidays should not have a community.")

        if leave_type and leave_type.leave.lower() == "community" and community is None:
            raise serializers.ValidationError("Community-based holidays must have a selected community.")

        return data

class LeaveTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = LeaveType
        fields = ['id', 'leave']  

class PasswordResetSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only = True)

    def validate(self, data):
        if data.get("new_password") != data.get("confirm_password"):
            raise serializers.ValidationError({"confirm_password":"Passwords do not match."})
        return data

class AttendanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attendance
        fields = '__all__'

class AttendanceRequestSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(required=False) 

    class Meta:
        model = AttendanceRequest
        fields = ['id', 'employee', 'date', 'check_in', 'check_out', 'work_type', 'location', 'status', 'image']
        read_only_fields = ['employee', 'status'] 

    def validate(self, data):
        """Ensure location is provided for field work"""
        if data.get("work_type") == "field" and not data.get("location"):
            raise serializers.ValidationError("Location is required for field work.")
        return data


class EmployeeShiftAssignmentSerializer(serializers.ModelSerializer):
    employee_name = serializers.CharField(source='employee.name', read_only=True)
    shift_type = serializers.CharField(source='shift.shift_type', read_only=True)

    class Meta:
        model = EmployeeShiftAssignment
        fields = ['id', 'date', 'employee', 'employee_name', 'shift', 'shift_type',]

class WorkingHoursSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkingHours
        fields = "__all__"



class EmployeeProfileSerializer(serializers.ModelSerializer):
    name = serializers.ReadOnlyField()
    email = serializers.ReadOnlyField(source="user.email")
    department = serializers.ReadOnlyField(source="user.department")

    class Meta:
        model = Employee
        fields = ["name", "email", "emp_num", "department", "priority", "image"]

class EmployeeSerializer(serializers.ModelSerializer):
    role = serializers.CharField(source="user.role", read_only=True)
    profile_picture = serializers.ImageField(source="image", read_only=True)
    attendance_status = serializers.SerializerMethodField()

    class Meta:
        model = Employee
        fields = ['id', 'name', 'role', 'profile_picture', 'attendance_status']

    def get_attendance_status(self, obj):
        latest_attendance = Attendance.objects.filter(employee=obj).order_by('-date').first()
        return latest_attendance.status if latest_attendance else "No Record"

class EmployeeSerializers(serializers.ModelSerializer):
    class Meta:
        model = Employee
        fields = "__all__" 

class EmployeesSerializers(serializers.ModelSerializer):
    class Meta:
        model = Employee
        fields = ["name", "id"]

class AttendanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attendance
        fields = ["date", "check_in", "check_out", "status"]

class OvertimeSerializer(serializers.ModelSerializer):
    employee_name = serializers.CharField(source='employee.name', read_only=True)
    class Meta:
        model = Overtime
        fields = ["date", "hours", "employee_name", "id", "reason"]

class EmployeeDetailSerializer(serializers.ModelSerializer):
    attendance = serializers.SerializerMethodField()
    total_overtime_hours = serializers.SerializerMethodField()
    total_unpaid_leaves = serializers.SerializerMethodField()

    class Meta:
        model = Employee
        fields = ["id", "user", "profile_image", "designation", "total_overtime_hours", "total_unpaid_leaves", "attendance"]

    def get_attendance(self, obj):
        attendance = Attendance.objects.filter(employee=obj).order_by("-date")
        return AttendanceSerializer(attendance, many=True).data

    def get_total_overtime_hours(self, obj):
        return Overtime.objects.filter(employee=obj).aggregate(total_hours=Sum("hours"))["total_hours"] or 0

    def get_total_unpaid_leaves(self, obj):
        """Calculate unpaid leaves based on exhausted leave quota"""
        leave_policies = LeavePolicy.objects.filter(employee=obj)
        leave_taken = LeaveRequest.objects.filter(employee=obj, status="approved").values("leave_type").annotate(count=Count("id"))

        leave_balance = {policy.leave_type: policy.allocated_leaves for policy in leave_policies}
        unpaid_leaves = 0

        for leave in leave_taken:
            leave_type = leave["leave_type"]
            taken_count = leave["count"]

            if taken_count > leave_balance.get(leave_type, 0):
                unpaid_leaves += (taken_count - leave_balance.get(leave_type, 0))

        return unpaid_leaves


class LeaveBalanceSerializer(serializers.Serializer):
    leave_type = serializers.CharField()
    allocated_leaves = serializers.IntegerField()
    used_leaves = serializers.IntegerField()
    remaining_leaves = serializers.IntegerField()


class EmployeeLeaveBalanceSerializer(serializers.ModelSerializer):
    leave_balances = serializers.SerializerMethodField()

    class Meta:
        model = Employee
        fields = ["id", "user", "designation", "leave_balances"]

    def get_leave_balances(self, obj):
        # Get leave balances for the employee
        leave_balances = LeaveBalance.objects.filter(employee=obj).select_related("leave_policy")

        # Get approved leave requests
        leave_taken = LeaveRequest.objects.filter(employee=obj, status="approved").values("leave_policy__leave_type").annotate(
            count=Count("id")
        )

        leave_taken_dict = {leave["leave_policy__leave_type"]: leave["count"] for leave in leave_taken}


        leave_summary = []
        for balance in leave_balances:
            leave_policy = balance.leave_policy  # Get associated leave policy
            leave_type = leave_policy.leave_type
            allocated = leave_policy.amount  # Use the correct field for allocated leaves
            used = leave_taken_dict.get(leave_type, 0)
            remaining = max(allocated - used, 0)

            leave_summary.append({
                "leave_type": leave_type,
                "allocated_leaves": allocated,
                "used_leaves": used,
                "remaining_leaves": remaining,
            })

        return leave_summary


class ManualAttendanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attendance
        fields = ["employee", "date", "check_in", "check_out", "status"]

    def validate(self, data):
        """Custom validation for attendance entries."""
        check_in = data.get("check_in")
        check_out = data.get("check_out")

        if check_in and check_out and check_in >= check_out:
            raise serializers.ValidationError("Check-out time must be after check-in time.")

        return data

    def create(self, validated_data):
        """Create or update attendance record for the given date."""
        attendance, created = Attendance.objects.update_or_create(
            employee=validated_data["employee"],
            date=validated_data["date"],
            defaults=validated_data
        )
        return attendance

logger = logging.getLogger(__name__)

class EmployeeAddSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)
    department = serializers.CharField(write_only=True)
    community = serializers.CharField(write_only=True)
    designation = serializers.CharField(write_only=True)
    emp_num = serializers.CharField(required=True)
    hire_date = serializers.DateField(required=True)
    image = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = Employee
        fields = ["id", "name", "email", "emp_num", "hire_date", "image", "department", "community", "designation"]

    def create(self, validated_data):
        email = validated_data.pop("email")
        department_name = validated_data.pop("department")
        community_name = validated_data.pop("community")
        designation_name = validated_data.pop("designation")

        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({"error": "User with this email already exists"})

        password = get_random_string(length=8)

        try:
            with transaction.atomic():
                # Ensure department exists
                department, _ = User.objects.get_or_create(name=department)
                community, _ = Community.objects.get_or_create(community_name=community_name)
                designation, _ = Designation.objects.get_or_create(desig_name=designation_name)

                # Create User
                user = User.objects.create(
                    username=email,
                    email=email,
                    department=department,
                    role="Employee",
                    password=make_password(password),
                )

                # Create Employee
                employee = Employee.objects.create(
                    user=user,
                    community=community,
                    designation=designation,
                    **validated_data
                )

                # Send reset link instead of plain password
                reset_link = f"https://yourdomain.com/reset-password?email={email}"
                send_mail(
                    subject="Your Account Credentials",
                    message=f"Hello {user.username},\n\nYour account has been created.\nUsername: {email}\nPlease reset your password using this link: {reset_link}\n\nBest Regards, Team",
                    from_email="presenceplussoftware@gmail.com",
                    recipient_list=[email],
                    fail_silently=False,
                )

            return employee

        except IntegrityError:
            raise serializers.ValidationError("Database error occurred while creating the employee.")
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            raise serializers.ValidationError("An unexpected error occurred.")

            
class EmployeeListSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source="user.email")  # ✅ Fetch from User model
    role = serializers.CharField(source="user.role")
    department = serializers.CharField(source="user.department")  # ✅ Fetch from User model
    designation = serializers.CharField(source="designation.desig_name", allow_null=True)  # ✅ Get Designation name
    community = serializers.CharField(source="community.community_name", allow_null=True)  # ✅ Get Community name

    class Meta:
        model = Employee        
        fields = ["id", "name", "email", "role", "emp_num", "hire_date", "status","designation", "community","department"]

class HRLeaveRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = LeaveRequest
        fields = "__all__"

class LeavePolicyUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = LeavePolicy
        fields = '__all__'

class LeavePolicyDropSerializer(serializers.ModelSerializer):
    class Meta:
        model = LeavePolicy
        fields = ['id', 'leave_type']

UserModel = get_user_model()

class AdminProfileSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source='employee.name')
    image = serializers.ImageField(source='employee.image', required=False)

    class Meta:
        model = User
        fields = ["email", "name", "image"]

    def update(self, instance, validated_data):
        employee_data = validated_data.pop("employee", {})
        
        # Update the User model (email is read-only)
        instance.save()

        # Update Employee model
        Employee.objects.update_or_create(user=instance, defaults=employee_data)

        return instance
    
class AttendanceStatsSerializer(serializers.Serializer):
    total_days = serializers.IntegerField()
    present_days = serializers.IntegerField()
    absent_days = serializers.IntegerField()
    late_days = serializers.IntegerField()
    total_overtime_hours = serializers.FloatField()
    attendance_percentage = serializers.FloatField()

class CommunitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Community
        fields = '__all__'

class DesignationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Designation
        fields = '__all__'

class LeaveRequestSerializers(serializers.ModelSerializer):
    employee_name = serializers.CharField(source="employee.name", read_only=True)
    designation = serializers.CharField(source="employee.designation.desig_name", read_only=True)
    leave_type = serializers.CharField(source="leave_policy.name", read_only=True)

    class Meta:
        model = LeaveRequest
        fields = [
            "id", "employee_name", "designation", "start_date", "end_date",
            "status", "reason", "reject_reason", "leave_type"
        ]

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = "__all__"