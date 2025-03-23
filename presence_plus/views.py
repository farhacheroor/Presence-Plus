from datetime import timedelta, date, time
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from rest_framework import status
import re
from django.db.models import F, Sum, Q
from django.db.models.functions import TruncMonth
from django.utils.encoding import force_str
from django.db import transaction
from django.utils import timezone
import pandas as pd
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.http import HttpResponse
from django.utils.crypto import get_random_string
from django.utils.dateparse import parse_date
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django_celery_beat.utils import now
from jwt.utils import force_bytes
import logging
from presence_plus.models import User  # Import your custom model directly
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status, permissions, generics, viewsets, mixins,filters
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.request import Request
from django.contrib.auth.models import User
from django.conf import settings
from presence_plus.models import *
from presence_plus.serializers import *
from presence_plus.tasks import *
import uuid
from rest_framework_simplejwt.authentication import JWTAuthentication


User = get_user_model()

class CreateUserView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access

    def post(self, request):
        emp_num = request.data.get("emp_num")
        name = request.data.get("name")
        department = request.data.get("department") 
        designation = request.data.get("designation")
        email = request.data.get("email")  # Allow manual password entry
        hire_date = request.data.get("hire_date")
        password = request.data.get("password")  # Manually enter hire_date
        username = email  # Use email as username

        # Get the current user's role
        current_role = getattr(request.user, "role", "").lower() if request.user else None

        # Determine the role to assign based on the creator's role
        if current_role == "admin":
            new_user_role = "hr"  # Admin can only create HR users
        elif current_role == "hr":
            new_user_role = "employee"  # HR can only create Employee users
        else:
            return Response({"error": "You do not have permission to create users"}, status=status.HTTP_403_FORBIDDEN)

        # Ensure all required fields are provided
        if not all([email, department, name, emp_num, hire_date]):
            return Response({"error": "All fields (email, department, name, emp_num, hire_date) are required"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate hire_date format
        try:
            hire_date = now().strptime(hire_date, "%Y-%m-%d").date()
        except ValueError:
            return Response({"error": "Invalid hire_date format. Use YYYY-MM-DD"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if email is already in use
        if User.objects.filter(email=email).exists():
            return Response({"error": "User with this email already exists"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if emp_num is unique
        if Employee.objects.filter(emp_num=emp_num).exists():
            return Response({"error": "Employee Number already exists"}, status=status.HTTP_400_BAD_REQUEST)

        # Generate a random password if not provided
        if not password:
            password = get_random_string(length=10)  # Generate a 10-character random password

        try:
            with transaction.atomic():  # Ensure database consistency
                # Create the new user with the assigned role
                user = User.objects.create(
                    email=email,
                    password=make_password(password),  # Hash the password before saving
                    role=new_user_role,  # Automatically assigned based on creator's role
                    department=department,
                    username=username
                )
                designation = Designation.objects.create(desig_name=designation)

                # Create Employee record if applicable
                if new_user_role in ["employee", "hr"]:
                    Employee.objects.create(
                        user=user,
                        name=name,
                        emp_num=emp_num,
                        hire_date=hire_date  # Manually entered
                    )

                # Send email with login credentials
                subject = "Your Account Has Been Created"
                message = f"""
                Hello {name},

                Your account has been successfully created.

                **Login Credentials:**
                - Email: {email}
                - Password: {password}

                Please log in and change your password immediately.

                Regards,
                Team Presence
                """
                send_mail(subject, message, settings.EMAIL_HOST_USER, [email])

            return Response({"message": f"{new_user_role.capitalize()} user created successfully. Credentials sent to email."}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#######     login   ##########################
User = get_user_model()

class LoginView(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)

        if not check_password(password, user.password):
            return Response({"error": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(user)

        role = user.role.lower()
        dashboard_url = {
            "admin": "/admin-dashboard",
            "hr": "/hr-dashboard",
            "employee": "/emp-dashboard"
        }.get(role, None)

        if not dashboard_url:
            return Response({"error": "Invalid role"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            "access": str(refresh.access_token),  # ✅ Fix key from 'token' to 'access'
            "refresh": str(refresh),
            "role": user.role,
            "redirect_url": dashboard_url,
        }, status=status.HTTP_200_OK)


################        forget password #####################
User = get_user_model()


class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Get the email from the request data
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Check if a user with the provided email exists
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Return a success message even if the user doesn't exist (to avoid leaking information)
            return Response({
                "message": "If an account with this email exists, you will receive a password reset email shortly."
            }, status=status.HTTP_200_OK)

        # Generate a password reset token and encode the user's primary key
        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(str(user.pk)))

        # Build the password reset URL
        # reset_url = f"{request.build_absolute_uri('/api/reset-password/')}?uid={uidb64}&token={token}"

        frontend_url = "http://192.168.251.97:5000"
        reset_url = f"{frontend_url}/reset-password/{uidb64}/{token}"

        # Prepare the email content
        subject = "Password Reset Request"
        message = (
            f"Hi {user.username},\n\n"
            "We received a request to reset your password. Click the link below to set a new password:\n"
            f"{reset_url}\n\n"
            "If you didn't request this, please ignore this email.\n"
            "Thank you."
        )

        try:
            # Debugging: Print email details
            # print(f"Attempting to send email to {user.email}...")  # Debugging
            # print(f"Reset URL: {reset_url}")  # Debugging
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            print("Email sent successfully!")  # Debugging
        except Exception as e:
            # Log the error and return a 500 response
            print(f"Error sending email: {e}")  # Debugging
            return Response({"error": "Failed to send email."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Return a success response
        return Response({
            "message": "If an account with this email exists, you will receive a password reset email shortly."
        }, status=status.HTTP_200_OK)

######################      reset password  #####################33
User = get_user_model()


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            uidb64 = serializer.validated_data.get('uid')
            token = serializer.validated_data.get('token')
            new_password = serializer.validated_data.get('new_password')

            try:
                # Decode the uidb64 to get the user id
                uid = force_str(urlsafe_base64_decode(uidb64))
                user = User.objects.get(pk=uid)
            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                return Response({"error": "Invalid uid."}, status=status.HTTP_400_BAD_REQUEST)

            # Validate the token
            token_generator = PasswordResetTokenGenerator()
            if not token_generator.check_token(user, token):
                return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password and save the user
            user.set_password(new_password)
            user.save()

            return Response({"message": "Password reset successful."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#################       editing role    #########################

class EditUserRoleView(APIView):
    def post(self, request, user_id):
        # Ensure that the currently logged-in user is either admin or hr
        current_user = request.user
        if current_user.role.lower() not in ["admin", "hr"]:
            return Response({"error": "Only admin and HR can edit user roles."}, status=status.HTTP_403_FORBIDDEN)

        # Get the user to update by user_id
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        new_role = request.data.get("role")
        if not new_role:
            return Response({"error": "Role is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure the role is one of the allowed roles
        if new_role.lower() not in ["hr", "employee"]:
            return Response({"error": "Invalid role"}, status=status.HTTP_400_BAD_REQUEST)

        # If the current user is admin, they can assign any role (HR or Employee)
        # If the current user is HR, they can only assign "employee" role
        if current_user.role.lower() == "hr" and new_role.lower() != "employee":
            return Response({"error": "HR can only assign the 'employee' role."}, status=status.HTTP_403_FORBIDDEN)

        # Update the user's role
        user.role = new_role.lower()
        user.save()

        return Response({"message": f"User role updated to {new_role}"}, status=status.HTTP_200_OK)

############    hr view #################

User = get_user_model()

class HRListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Fetch HR users and join with Employee table to get the name
        hr_users = User.objects.filter(role__iexact="hr").select_related("employee").values(
            "id", "email", "role", "department", "employee__name"
        )

        if not hr_users:
            return Response({"message": "No HR users found."}, status=status.HTTP_404_NOT_FOUND)

        return Response({"hr_users": list(hr_users)}, status=status.HTTP_200_OK)

#############       delete      ######################

class Delete(APIView):
    permission_classes = [IsAuthenticated]  # Only authenticated users can delete HR

    def delete(self, request, hr_id):
        user = request.user  # Get the currently logged-in user

        # Ensure only Admins can delete HR users
        if user.role.lower() != "admin":
            return Response({"error": "Only Admins can delete HR users"}, status=status.HTTP_403_FORBIDDEN)

        try:
            hr_user = User.objects.get(id=hr_id, role__iexact="hr")
            hr_user.delete()
            return Response({"message": "HR user deleted successfully."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "HR user not found."}, status=status.HTTP_404_NOT_FOUND)

#################   admin profile   #############################

User = get_user_model()

class AdminProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = AdminProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

#################       dashboard admin view       ########################

User = get_user_model()

class DashboardCountsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        total_employees = User.objects.filter(role__iexact="Employee").count()
        total_hr = User.objects.filter(role__iexact="HR").count()

        # Use iexact for case-insensitive filtering
        leave_requests = LeaveRequest.objects.filter(status__iexact="pending").count()
        leave_cancellations = LeaveRequest.objects.filter(status__iexact="cancelled").count()

        return Response({
            "total_employees": total_employees,
            "total_hr": total_hr,
            "leave_requests": leave_requests,
            "leave_cancellations": leave_cancellations
        }, status=status.HTTP_200_OK)

##################      admin dashboard statistics  ###############

class AttendanceStatsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        period = request.query_params.get("period", "weekly")  # Default to weekly
        today = datetime.now().date()

        if period == "weekly":
            start_date = today - timedelta(days=today.weekday())  # Start of the week (Monday)
        elif period == "monthly":
            start_date = today.replace(day=1)  # Start of the month
        else:
            return Response({"error": "Invalid period. Use 'weekly' or 'monthly'."}, status=status.HTTP_400_BAD_REQUEST)

        # Filter attendance records within the selected period
        attendance_data = Attendance.objects.filter(date__gte=start_date, date__lte=today)

        present_count = attendance_data.filter(status="present").count()
        absent_count = attendance_data.filter(status="absent").count()
        late_count = attendance_data.filter(status="late").count()


        return Response({
            "present": present_count,
            "absent": absent_count,
            "late": late_count
        }, status=status.HTTP_200_OK)

###############     Leave request view  ##################
logger = logging.getLogger('leave')

class LeaveRequestListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            logger.info(f"User role: {request.user.role}")  # Debug log
            
            # If Admin, show only leave requests where the employee is an HR
            if request.user.role.lower() == "admin":
                leave_requests = LeaveRequest.objects.all()#filter(employee__user__role="hr" and "admin")

            # If HR, show all leave requests
            elif request.user.role.lower() == "hr":
                leave_requests = LeaveRequest.objects.all()

            # Employees should only see their own leave requests
            else:
                leave_requests = LeaveRequest.objects.filter(employee__user=request.user)

            logger.info(f"Leave Requests: {leave_requests}")  # Log queryset

            serializer = LeaveRequestSerializer(leave_requests, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error fetching leave requests: {e}")  # Log error
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

###############     leave approve or reject #################

class ManageLeaveRequestView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]  # Ensure only logged-in users can access

    def post(self, request, leave_id):
        try:
            # Fetch the leave request (404 if not found)
            leave_request = get_object_or_404(LeaveRequest, id=leave_id)

            # Ensure only HR/Admin can approve/reject
            if request.user.role.lower() not in ["hr", "admin"]:
                return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)

            action = request.data.get("action")  # Expected: "approve" or "reject"

            # Validate action
            if action not in ["approve", "reject"]:
                return Response({"error": "Invalid action. Use 'approve' or 'reject'."}, status=status.HTTP_400_BAD_REQUEST)

            # Prevent modifying an already processed request
            if leave_request.status in ["approved", "rejected"]:
                return Response({"error": f"Leave request is already {leave_request.status}"}, status=status.HTTP_400_BAD_REQUEST)

            # Update status based on action
            leave_request.status = "approved" if action == "approve" else "rejected"
            leave_request.save()

            return Response({"message": f"Leave request {action}d successfully!"}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

###########     leave cancellation approve/ reject  #####################

class ManageCancellationRequestView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]  # Only admins can approve/reject

    def post(self, request, leave_id):
        try:
            leave_request = LeaveRequest.objects.get(id=leave_id)

            if not leave_request.cancellation_request:
                return Response({"error": "No cancellation request for this leave"}, status=status.HTTP_400_BAD_REQUEST)

            action = request.data.get("action")  # "approve" or "reject"

            if action == "approve":
                leave_request.status = "cancelled"
                leave_request.cancellation_request = False
            elif action == "reject":
                leave_request.cancellation_request = False  # Reset request
            else:
                return Response({"error": "Invalid action"}, status=status.HTTP_400_BAD_REQUEST)

            leave_request.save()
            return Response({"message": f"Cancellation request {action}d successfully"}, status=status.HTTP_200_OK)

        except LeaveRequest.DoesNotExist:
            return Response({"error": "Leave request not found"}, status=status.HTTP_404_NOT_FOUND)

#################       attendance report generator ########################

class AttendanceReportView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        report_format = request.GET.get("format", "json")  # Default to JSON
        start_date = request.GET.get("start_date")
        end_date = request.GET.get("end_date")
        #department = request.GET.get("department")

        start_date = parse_date(start_date) if start_date else None
        end_date = parse_date(end_date) if end_date else None

        employees = Employee.objects.all()

        # if department:
        #     employees = employees.filter(user__department=department)

        report_data = []
        for emp in employees:
            attendance_qs = Attendance.objects.filter(employee=emp)

            if start_date and end_date:
                attendance_qs = attendance_qs.filter(date__range=[start_date, end_date])

            # Ensuring attendance records exist before processing
            if not attendance_qs.exists():
                continue  # Skip employees with no attendance data

            total_working_days = attendance_qs.count()
            overtime = attendance_qs.filter(overtime=True).count()
            leave_days = attendance_qs.filter(status="leave").count()

            report_data.append({
                "Employee Name": emp.name,
                "Employee ID": emp.emp_num,
                "Department": emp.user.department if emp.user else "N/A",
                "Total Working Days": total_working_days,
                "Overtime Hours": overtime,
                "Leaves Taken": leave_days,
            })

        if not report_data:
            return Response(
                {"message": "No attendance records found for the selected filters"},
                status=status.HTTP_200_OK,
            )

        if report_format == "excel":
            return self.generate_excel(report_data)
        return Response(report_data, status=status.HTTP_200_OK)

    def generate_excel(self, data):
        df = pd.DataFrame(data)
        response = HttpResponse(content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        response["Content-Disposition"] = 'attachment; filename="attendance_report.xlsx"'
        df.to_excel(response, index=False)
        return response

#################  leave policy creation #############

class LeavePolicyCreateView(viewsets.ModelViewSet):
    queryset = LeavePolicy.objects.all()
    serializer_class = LeavePolicySerializer

    def destroy(self, request, *args, **kwargs):
        """Mark policy as inactive instead of deleting"""
        instance = self.get_object()
        instance.status = "inactive"
        instance.save()
        return Response({"message": "Policy marked as inactive"}, status=status.HTTP_200_OK)

########### policy view ################

class LeavePolicyViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing leave policies.
    """
    queryset = LeavePolicy.objects.all().order_by('-id')  # Fetch all policies, ordered by latest
    serializer_class = LeavePolicySerializer

    def list(self, request, *args, **kwargs):
        """
        GET method: Retrieve all leave policies.
        """
        policies = self.get_queryset()
        serializer = self.get_serializer(policies, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def retrieve(self, request, pk=None):
        """
        GET method: Retrieve a single leave policy by ID.
        """
        try:
            policy = LeavePolicy.objects.get(pk=pk)
            serializer = self.get_serializer(policy)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except LeavePolicy.DoesNotExist:
            return Response({"error": "Leave policy not found"}, status=status.HTTP_404_NOT_FOUND)

############    leave policy updation   #############

class LeavePolicyDetailView(viewsets.GenericViewSet,
                         mixins.RetrieveModelMixin,
                         mixins.UpdateModelMixin,
                         mixins.DestroyModelMixin):
    """
    ViewSet for handling:
    - GET: Retrieve a single leave policy
    - PUT/PATCH: Update a leave policy
    - DELETE: Delete a leave policy
    """
    queryset = LeavePolicy.objects.all()
    serializer_class = LeavePolicyUpdateSerializer

########### work policy creation and updation   #############

class WorkTimePolicyCreateListView(viewsets.ModelViewSet):
    """
    Handles:
    - GET: List all work time policies
    - POST: Create a new work time policy
    """
    queryset = WorkingHours.objects.all()
    serializer_class = WorkTimePolicySerializer


class WorkTimePolicyDetailView(viewsets.ModelViewSet):
    """
    Handles:
    - GET: Retrieve a specific work time policy
    - PUT/PATCH: Update a work time policy
    - DELETE: Delete a work time policy
    """
    queryset = WorkingHours.objects.all()
    serializer_class = WorkTimePolicySerializer

########### Holiday policy creation & updation  ############

class PublicHolidayViewSet(viewsets.ModelViewSet):
    queryset = PublicHoliday.objects.all()
    serializer_class = PublicHolidaySerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ['name', 'leave_type__leave', 'status']

    def get_queryset(self):
        """
        Filters public holidays based on leave type and status.
        Example usage:
        `/api/public-holidays/?leave_type=public`
        `/api/public-holidays/?status=active`
        """
        queryset = super().get_queryset()
        leave_type_param = self.request.query_params.get('leave_type')
        status_param = self.request.query_params.get('status')

        if leave_type_param:
            queryset = queryset.filter(leave_type__leave__iexact=leave_type_param)

        if status_param:
            queryset = queryset.filter(status__iexact=status_param)

        return queryset
        
    def create(self, request, *args, **kwargs):
        mutable_data = request.data.copy()  # Make a mutable copy of request data

        leave_type_name = mutable_data.get("leave_type")

        if not leave_type_name:
            raise ValidationError({"leave_type": "This field is required."})

        # Check if the leave type exists in the LeaveType model
        try:
            leave_type = LeaveType.objects.get(leave=leave_type_name)
        except LeaveType.DoesNotExist:
            raise ValidationError({"leave_type": "Selected leave type does not exist. Please create it first."})

        # Assign the ID of the existing leave type
        mutable_data["leave_type"] = leave_type.id  

        # Manually call the serializer with the updated data
        serializer = self.get_serializer(data=mutable_data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        return Response(serializer.data, status=status.HTTP_201_CREATED)

class LeaveTypeViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing Leave Types.
    """
    queryset = LeaveType.objects.all()
    serializer_class = LeaveTypeSerializer

    def get_queryset(self):
        return LeaveType.objects.all()

    def create(self, request, *args, **kwargs):
        """
        Handles creating a new leave type.
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Leave type created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#################   logout  ##############
class LogoutView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()  # ✅ Blacklist the token to invalidate it
                return Response({"message": "Successfully logged out"}, status=200)
            return Response({"error": "Refresh token is required"}, status=400)
        except Exception as e:
            return Response({"error": str(e)}, status=500)

#############   Employee dashboard  #############

class EmployeeDashboardView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        employee = request.user.employee
        today = date.today()
        first_day_of_month = today.replace(day=1)

        # Fetch today's attendance
        attendance = Attendance.objects.filter(employee=employee, date=today).first()
        check_in = attendance.check_in if attendance else None
        check_out = attendance.check_out if attendance else None
        late_status = attendance.status == "late" if attendance else False

        # # Fetch today's shift
        # shift_assignment = EmployeeShiftAssignment.objects.select_related('shift').filter(
        #     employee=employee, date=today
        # ).first()
        # shift = shift_assignment.shift.shift_type if shift_assignment else "Not Assigned"

        # Fetch overtime data
        overtime_today = Overtime.objects.filter(employee=employee, date=today).aggregate(Sum("hours"))["hours__sum"] or 0
        total_overtime = Overtime.objects.filter(employee=employee).aggregate(Sum("hours"))["hours__sum"] or 0

        # Calculate monthly attendance percentage
        total_working_days = Attendance.objects.filter(employee=employee, date__gte=first_day_of_month).count()
        present_days = Attendance.objects.filter(employee=employee, date__gte=first_day_of_month, status="present").count()
        attendance_percentage = round((present_days / total_working_days * 100), 2) if total_working_days else 0

        # ✅ Fetch daily attendance for graphical representation
        attendance_graph_data = []
        for day in range(1, today.day + 1):
            date_obj = first_day_of_month.replace(day=day)
            status = Attendance.objects.filter(employee=employee, date=date_obj).first()
            status_value = 1 if status and status.status == "present" else 0  # Present = 1, Absent = 0
            attendance_graph_data.append({"date": date_obj.strftime("%d %b"), "status": status_value})

        return Response({
            "check_in": check_in.strftime("%H:%M:%S") if check_in else "Not Available",
            "check_out": check_out.strftime("%H:%M:%S") if check_out else "Not Available",
            "late": late_status,
            "overtime_today": f"{overtime_today} hours",
            "total_overtime": f"{total_overtime} hours",
            "attendance_percentage": attendance_percentage,
            # "shift": shift,
            "date": today.strftime("%d %b"),
            "attendance_graph_data": attendance_graph_data  # ✅ Graph Data
        })

#################   employee leave request and history view ##########################

logger = logging.getLogger(__name__)  # ✅ Proper Logging Setup

class LeaveRequestView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            employee = request.user.employee
            start_date = request.data.get("start_date")
            end_date = request.data.get("end_date")
            leave_type_id = request.data.get("leave_type")  # Should be LeavePolicy ID
            reason = request.data.get("reason")
            image = request.FILES.get("image")  

            if not start_date or not end_date or not leave_type_id or not reason:
                return Response({"error": "All fields are required!"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                leave_type_id = int(leave_type_id)
            except ValueError:
                return Response({"error": "leave_type must be an integer!"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                start_date = date.fromisoformat(start_date)
                end_date = date.fromisoformat(end_date)
            except ValueError:
                return Response({"error": "Invalid date format! Use YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)

            if start_date > end_date:
                return Response({"error": "start_date cannot be after end_date!"}, status=status.HTTP_400_BAD_REQUEST)

            # ✅ Fetch Leave Policy (Instead of LeaveType)
            leave_policy = get_object_or_404(LeavePolicy, id=leave_type_id)
            leave_type = leave_policy.leave_type  # ✅ Extract the leave type

            # ✅ Fetch Leave Balance
            leave_balance = LeaveBalance.objects.filter(employee=employee, leave_policy=leave_policy).first()
            if not leave_balance:
                return Response({"error": "Leave balance not found!"}, status=status.HTTP_404_NOT_FOUND)

            available_days = max((leave_balance.total or 0) - (leave_balance.used or 0), 0)
            requested_days = (end_date - start_date).days + 1

            if requested_days > available_days:
                return Response({"error": "Insufficient leave balance!"}, status=status.HTTP_400_BAD_REQUEST)

            # ✅ Create Leave Request
            leave_request = LeaveRequest.objects.create(
                employee=employee,
                start_date=start_date,
                end_date=end_date,
                status="Pending",
                reason=reason,
                leave_policy=leave_policy,
                image=image,
            )

            # ✅ Update Leave Balance
            leave_balance.used += requested_days
            leave_balance.save()

            # ✅ Create Leave Transaction
            LeaveTransaction.objects.create(
                employee=employee,
                transaction_type="Leave Request",
                date=date.today(),
                debit=requested_days,
                pending=True,
                leave_policy=leave_policy
            )

            return Response({"message": "Leave request submitted successfully!"}, status=status.HTTP_201_CREATED)

        except Employee.DoesNotExist:
            return Response({"error": "Employee record not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get(self, request):
        try:
            employee = request.user.employee
            leave_requests = LeaveRequest.objects.filter(employee=employee).order_by("-start_date")

            data = [
                {
                    "id": lr.id,
                    "leave_type": lr.leave_policy.leave_type if isinstance(lr.leave_policy.leave_type, str) else lr.leave_policy.leave_type.name,
                    "start_date": lr.start_date,
                    "end_date": lr.end_date,
                    "status": lr.status,
                    "reason": lr.reason,
                    "cancellation_request": lr.cancellation_request,
                    "image": request.build_absolute_uri(lr.image.url) if lr.image else None,
                }
                for lr in leave_requests
            ]

            return Response(data, status=status.HTTP_200_OK)

        except Employee.DoesNotExist:
            return Response({"error": "Employee record not found"}, status=status.HTTP_404_NOT_FOUND)


class LeaveTypeListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    logger = logging.getLogger(__name__)  

    def get(self, request):
        try:
            logger.info("🚀 API Request Received!")

            employee = Employee.objects.get(user=request.user)
            logger.info(f"Authenticated Employee: {employee}")

            # ✅ Fetch leave balances
            leave_balances = LeaveBalance.objects.filter(employee=employee).annotate(
                balance=F("total") - F("used")
            ).filter(balance__gt=0)

            logger.info(f"Leave Balances Retrieved: {list(leave_balances.values('id', 'total', 'used', 'balance'))}")

            # ✅ Extract leave policies
            leave_policies = [lb.leave_policy for lb in leave_balances if lb.balance > 0]
            logger.info(f"Leave Policies Extracted: {leave_policies}")

            # ✅ Prepare response data
            data = [{"id": lp.id, "name": lp.leave_type} for lp in leave_policies]
            logger.info(f"Response Data: {data}")

            return Response(data, status=status.HTTP_200_OK)

        except Employee.DoesNotExist:
            logger.error(f"Employee not found for user {request.user}")
            return Response({"error": "Employee record not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Unexpected error in LeaveTypeListView: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

###########     leave balance view  ##############
class LeaveBalanceSummaryView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Retrieve total available and used leave for the logged-in employee."""
        try:
            employee = request.user.employee

            # Get all leave balances for the employee
            leave_balances = LeaveBalance.objects.filter(employee=employee)

            # Calculate total leave and used leave
            total_leave = sum(lb.total for lb in leave_balances)
            used_leave = sum(lb.used for lb in leave_balances)
            available_leave = total_leave - used_leave  # Remaining leave

            # Prepare response data
            data = {
                "total_leave": total_leave,
                "used_leave": used_leave,
                "available_leave": available_leave
            }

            return Response(data, status=status.HTTP_200_OK)

        except Employee.DoesNotExist:
            return Response({"error": "Employee record not found"}, status=status.HTTP_404_NOT_FOUND)

#############   Leave cancellation required ####################

class LeaveCancellationRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, leave_id):
        """Employee requests leave cancellation (Needs HR approval)"""
        try:
            leave_request = LeaveRequest.objects.get(
                id=leave_id, employee=request.user.employee, status="Approved"
            )
        except LeaveRequest.DoesNotExist:
            return Response({"error": "Leave request not found or cannot be cancelled!"}, status=status.HTTP_404_NOT_FOUND)

        # Update leave to pending cancellation
        leave_request.cancellation_request = True
        leave_request.status = "Cancellation Pending"
        leave_request.save()

        # Create leave transaction entry
        LeaveTransaction.objects.create(
            employee=request.user.employee,
            transaction_type="Cancellation Request",
            date=date.today(),
            pending=True
        )

        return Response({"message": "Leave cancellation request submitted successfully!"}, status=status.HTTP_200_OK)

###############     HR leave cancellation view  #################################

class LeaveCancellationApprovalView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, leave_id):
        """HR approves or rejects leave cancellation"""
        if request.user.role != "HR":
            return Response({"error": "Unauthorized action!"}, status=status.HTTP_403_FORBIDDEN)

        decision = request.data.get("decision")  # Accept or Reject
        try:
            leave_request = LeaveRequest.objects.get(id=leave_id, status="Cancellation Pending")
        except LeaveRequest.DoesNotExist:
            return Response({"error": "Cancellation request not found!"}, status=status.HTTP_404_NOT_FOUND)

        if decision.lower() == "approve":
            leave_request.status = "Cancelled"
            leave_request.save()

            # Refund leave balance
            requested_days = (leave_request.end_date - leave_request.start_date).days + 1
            leave_balance = LeaveBalance.objects.filter(employee=leave_request.employee).first()
            if leave_balance:
                leave_balance.available_days += requested_days
                leave_balance.save()

            # Update transaction as completed
            LeaveTransaction.objects.create(
                employee=leave_request.employee,
                transaction_type="Leave Cancellation Approved",
                date=date.today(),
                credit=requested_days
            )

            return Response({"message": "Leave cancellation approved successfully!"}, status=status.HTTP_200_OK)

        elif decision.lower() == "reject":
            leave_request.status = "Approved"  # Revert back to approved leave
            leave_request.cancellation_request = False
            leave_request.save()

            # Mark transaction as rejected
            LeaveTransaction.objects.create(
                employee=leave_request.employee,
                transaction_type="Leave Cancellation Rejected",
                date=date.today(),
                pending=False
            )

            return Response({"message": "Leave cancellation rejected!"}, status=status.HTTP_200_OK)

        return Response({"error": "Invalid decision value!"}, status=status.HTTP_400_BAD_REQUEST)

################    employee overtime view  #####################
from django.db.models.functions import TruncMonth
class OvertimeStatsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Retrieve overtime stats grouped by month"""
        employee = request.user.employee

        # Group by month and calculate total overtime hours per month
        overtime_data = (
            Overtime.objects.filter(employee=employee, status="completed")
            .annotate(month=TruncMonth("date"))  # ✅ Fix: TruncMonth now works
            .values("month")
            .annotate(total_hours=Sum("hours"))
            .order_by("month")
        )

        # Convert the data into a more readable format (Month Name → Hours)
        monthly_overtime = {entry["month"].strftime("%b"): entry["total_hours"] for entry in overtime_data}

        # Get total overtime hours
        total_hours = sum(monthly_overtime.values())

        # Get current month stats
        current_month = datetime.now().strftime("%b")
        selected_month_hours = monthly_overtime.get(current_month, 0)

        return Response(
            {
                "monthly_overtime": monthly_overtime,
                "total_hours": total_hours,
                "selected_month": {"month": current_month, "hours": selected_month_hours},
            },
            status=status.HTTP_200_OK,
        )

class OvertimeAssignmentView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """Retrieve upcoming, missed, and completed overtime assignments"""
        try:
            # Get the employee object
            employee = getattr(request.user, "employee", None)
            if not employee:
                return Response({"error": "Employee record not found"}, status=status.HTTP_404_NOT_FOUND)

            print(f"Employee ID: {employee.id}")  # Debugging line

            # Fetch the employee's latest attendance record
            latest_attendance = Attendance.objects.filter(employee=employee).order_by("-date").first()

            if latest_attendance:
                print(f"Latest Check-out Time: {latest_attendance.check_out}")  # Debugging line

                # Ensure check_out is a datetime object
                latest_checkout_datetime = datetime.combine(latest_attendance.date, latest_attendance.check_out)

                # Get all overtime entries assigned to this employee
                overtime_entries = Overtime.objects.filter(employee=employee, status__in=["upcoming", "missed"])

                for overtime in overtime_entries:
                    overtime_end_time = datetime.combine(overtime.date, time(0, 0)) + timedelta(hours=overtime.hours)
                    today = datetime.now().date()

                    if overtime.date > today:
                    # Future overtime should remain "upcoming"
                        overtime.status = "upcoming"
                    elif latest_checkout_datetime >= overtime_end_time:
                    # Overtime is completed
                        overtime.status = "completed"
                    else:
                    # If overtime date has passed and was not completed, it's missed
                        overtime.status = "missed"

                    overtime.save()  # ✅ Save the updated status

            # Retrieve updated overtime records
            upcoming_overtime = list(Overtime.objects.filter(employee=employee, status="upcoming").values("date", "hours", "reason"))
            missed_overtime = list(Overtime.objects.filter(employee=employee, status="missed").values("date", "hours", "reason"))
            completed_overtime = list(Overtime.objects.filter(employee=employee, status="completed").values("date", "hours", "reason"))

            print("Upcoming Overtime:", upcoming_overtime)  # Debugging line
            print("Missed Overtime:", missed_overtime)  # Debugging line
            print("Completed Overtime:", completed_overtime)  # Debugging line

            return Response(
                {
                    "upcoming_overtime": upcoming_overtime,
                    "missed_overtime": missed_overtime,
                    "completed_overtime": completed_overtime,
                },
                status=status.HTTP_200_OK,
            )

        except Employee.DoesNotExist:
            return Response({"error": "Employee record not found"}, status=status.HTTP_404_NOT_FOUND)
############    employee attendance stat    ##################
class MonthlyAttendanceStatisticsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        employee = request.user.employee

        # Get month and year from frontend request (default to current month & year)
        month = request.GET.get("month")
        year = request.GET.get("year")

        if not month or not year:
            return Response({"error": "Month and year are required."}, status=400)

        month = int(month)
        year = int(year)

        # Calculate first and last day of the selected month
        first_day_of_month = date(year, month, 1)
        last_day_of_month = (first_day_of_month.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)

        # Count attendance records for the selected month
        attendance_counts = Attendance.objects.filter(
            employee=employee,
            date__range=(first_day_of_month, last_day_of_month)
        ).values("status").annotate(count=Count("status"))

        # Initialize attendance counts
        total_days = (last_day_of_month - first_day_of_month).days + 1
        present_count = 0
        late_count = 0
        absent_count = 0

        # Populate attendance counts based on fetched records
        for record in attendance_counts:
            if record["status"] == "present":
                present_count = record["count"]
            elif record["status"] == "late":
                late_count = record["count"]
            elif record["status"] == "absent":
                absent_count = record["count"]

        # Calculate percentages (avoid division by zero)
        if total_days > 0:
            present_percentage = round((present_count / total_days) * 100, 2)
            late_percentage = round((late_count / total_days) * 100, 2)
            absent_percentage = round((absent_count / total_days) * 100, 2)
        else:
            present_percentage = late_percentage = absent_percentage = 0

        return Response({
            "month": first_day_of_month.strftime("%B"),
            "year": year,
            "total_days": total_days,
            "attendance_statistics": {
                "present": {"count": present_count, "percentage": present_percentage},
                "late": {"count": late_count, "percentage": late_percentage},
                "absent": {"count": absent_count, "percentage": absent_percentage},
            },
        }, status=200)

###########     employee attendance manual request and view ##################

class AttendanceListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """Fetch attendance records and manual attendance requests for the logged-in employee"""
        try:
            employee = request.user.employee

            # Fetch attendance records
            attendance_records = Attendance.objects.filter(employee=employee)

            # Fetch manual attendance requests
            attendance_requests = AttendanceRequest.objects.filter(employee=employee)

            # Serialize Attendance data
            attendance_data = [
                {
                    "id": att.id,
                    "date": att.date,
                    "check_in": att.check_in,
                    "check_out": att.check_out,
                    "status": "Approved",  # Since Attendance records are already approved
                    "work_type":  getattr(att, "work_type", None),
                    "location": getattr(att, "location", None),
                    "image": request.build_absolute_uri(att.image.url) if hasattr(att, "image") and att.image else None,
                }
                for att in attendance_records
            ]

            # Serialize Attendance Request data
            request_data = [
                {
                    "id": req.id,
                    "date": req.date,
                    "check_in": req.check_in,
                    "check_out": req.check_out,
                    "status": req.status,  # Pending, Approved, or Rejected
                    "work_type":  getattr(req, "work_type", None),
                    "location": getattr(req, "location", None),
                    "image": request.build_absolute_uri(req.image.url) if hasattr(req, "image") and req.image else None,
                }
                for req in attendance_requests
            ]

            # Combine both lists
            response_data = attendance_data + request_data

            return Response(response_data, status=status.HTTP_200_OK)

        except Employee.DoesNotExist:
            return Response({"error": "Employee record not found"}, status=status.HTTP_404_NOT_FOUND)


class AttendanceRequestView(generics.ListCreateAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AttendanceRequestSerializer

    def get_queryset(self):
        return AttendanceRequest.objects.filter(employee=self.request.user.employee)  # ✅ Get employee's records

    def perform_create(self, serializer):
        """Ensure employee is correctly assigned and date is set to today"""
        employee = self.request.user.employee  # ✅ Get the Employee instance
        today = date.today()  # ✅ Get today's date
        serializer.save(employee=employee, date=today)

class AttendanceRequestApprovalView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]  # Only HR/Admin can approve/reject requests

    def post(self, request, pk):
        try:
            attendance_request = AttendanceRequest.objects.get(pk=pk)
            status = request.data.get("status")

            if status not in ["approved", "rejected","pending"]:
                return Response({"error": "Invalid status"}, status=400)

            attendance_request.status = status
            attendance_request.save()

            if status == "approved":
                Attendance.objects.create(
                    employee=attendance_request.employee,
                    date=attendance_request.date,
                    check_in=attendance_request.check_in,
                    check_out=attendance_request.check_out,
                    status="present"
                )

            return Response({"message": f"Request {status} successfully"})
        except AttendanceRequest.DoesNotExist:
            return Response({"error": "Request not found"}, status=404)

###############     HR shift assignment ##################
class WorkingHoursViewSet(viewsets.ModelViewSet):
    queryset = WorkingHours.objects.all()
    serializer_class = WorkingHoursSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

class ShiftRosterViewSet(viewsets.ModelViewSet):
    queryset = ShiftRoster.objects.all()
    serializer_class = ShiftRosterSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

class EmployeeViewSet(viewsets.ModelViewSet):
    queryset = Employee.objects.all()
    serializer_class = EmployeeSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

class EmployeeShiftAssignmentViewSet(viewsets.ModelViewSet):
    authentication_classes = [JWTAuthentication]
    queryset = EmployeeShiftAssignment.objects.all()
    serializer_class = EmployeeShiftAssignmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        date = self.request.query_params.get('date', None)
        if date:
            return self.queryset.filter(date=date)
        return self.queryset

    def perform_create(self, serializer):
        serializer.save()

############    Employee shift view ##############

class EmployeeShiftView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]  # Only logged-in employees can view shifts

    def get(self, request):
        date = request.GET.get("date")
        shift_assignment = EmployeeShiftAssignment.objects.filter(employee=request.user, date=date).select_related(
            "shift").first()

        if shift_assignment:
            shift_data = {
                "date": date,
                "shift": shift_assignment.shift.shift_type,
                "start_time": shift_assignment.shift.start_time,
                "end_time": shift_assignment.shift.end_time
            }
            return Response(shift_data)

        return Response({"message": "No shift assigned for this date"}, status=404)

class ShiftRosterView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]  # Only HR/Admin can view shift rosters

    def get(self, request):
        roster_id = request.GET.get("roster_id")
        shifts = EmployeeShiftAssignment.objects.filter(shift_roster_id=roster_id).select_related("employee", "shift")

        if not shifts.exists():
            return Response({"message": "No shifts assigned for this roster"}, status=404)

        data = [
            {
                "employee": shift.employee.name,
                "date": shift.date,
                "shift": shift.shift.shift_type,
                "start_time": shift.shift.start_time,
                "end_time": shift.shift.end_time,
            }
            for shift in shifts
        ]
        return Response(data)

############    employee profile    ##################################

class EmployeeProfileView(APIView):
    authentication_classes = [JWTAuthentication]  # ✅ Enforce JWT authentication
    permission_classes = [IsAuthenticated]  # ✅ Ensure only authenticated users can access

    def get(self, request):
        print("Authenticated user:", request.user)  # Debugging
        if request.user.is_anonymous:
            return Response({"error": "User is not authenticated"}, status=401)

        employee = Employee.objects.select_related("user").get(user=request.user)

        profile_data = {
            "name": employee.name,
            "email": employee.user.email,
            "employee_id": employee.emp_num,
            "hire_date": employee.hire_date,
            "department": employee.user.department,
            "position": employee.designation.desig_name if employee.designation else None,
            "community_name": employee.community.community_name if employee.community else None,
            "image": request.build_absolute_uri(employee.image.url) if employee.image else None
        }

        return Response(profile_data)

    def patch(self, request):
        employee = Employee.objects.get(user=request.user)

        if "image" in request.data:
            employee.image = request.data["image"]
            employee.save()

            return Response({
                "message": "Profile updated successfully",
                "profile_image": request.build_absolute_uri(employee.image.url) if employee.image else None # ✅ Return full image URL
            })

        return Response({"error": "Only profile image can be updated"}, status=400)

################    change password #####################

class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request):
        user = request.user
        current_password = request.data.get("current_password")
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        # ✅ Validate Current Password
        if not check_password(current_password, user.password):
            return Response({"error": "Current password is incorrect"}, status=400)

        # ✅ Check if New Passwords Match
        if new_password != confirm_password:
            return Response({"error": "New passwords do not match"}, status=400)

        # ✅ Password Strength Validation
        if not self.validate_password_strength(new_password):
            return Response(
                {
                    "error": "Password must be at least 8 characters long, include a number, an uppercase letter, and a special character."},
                    status=400
                )

        # ✅ Set New Password
        user.set_password(new_password)
        user.save()

        return Response({"message": "Password updated successfully"}, status=200)

    def validate_password_strength(self, password):
        """Ensure password is strong."""
        return (
            len(password) >= 8 and
            re.search(r"\d", password) and  # At least one digit
            re.search(r"[A-Z]", password) and  # At least one uppercase letter
            re.search(r"[@$!%*?&#]", password)  # At least one special character
        )

###############     employee leave balance and history  ################

class EmployeeLeaveBalanceView(generics.RetrieveAPIView):
    queryset = Employee.objects.all()
    serializer_class = EmployeeLeaveBalanceSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_queryset(self):
        return Employee.objects.filter(id=self.kwargs["pk"])

class LeaveHistoryView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        employee = request.user.employee  # Get logged-in employee

        # Fetch all leave transactions (approved leaves taken)
        leave_history = LeaveTransaction.objects.filter(employee=employee, debit__gt=0).order_by("-date")

        # Formatting response
        history_data = []
        for leave in leave_history:
            leave_type = leave.leave_policy if leave.leave_policy else None
            history_data.append({
                "leave_type": leave_type.leave_type if leave_type else "Unknown",
                "date": leave.date.strftime("%d %B"),  # Example: "05 June"
                "days": leave.debit,
            })

        return Response({"leave_history": history_data}, status=200)

############    policy view ###############

class PolicyListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Fetch only active leave policies
        leave_policies = LeavePolicy.objects.filter(status="active").values(
            "leave_type", "carry_forward", "amount", "frequency"
        )

        # Fetch only active public holidays (Fix: Change "leave_type" to "leavetype")
        public_holidays = PublicHoliday.objects.filter(status="active").values(
            "name", "date", "leavetype", "community__community_name"
        )

        # Fetch only active working hours
        working_hours = WorkingHours.objects.filter(status="active").values(
            "shift_type", "start_time", "end_time"
        )

        return Response({
            "leave_policies": list(leave_policies),
            "public_holidays": list(public_holidays),  # Updated field name
            "working_hours": list(working_hours),
        }, status=200)

################    HR dashboard    ###############

class HRDashboardView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        today = now().date()

        # Total employees
        total_employees = Employee.objects.filter(user__role="Employee" or "employee").count()

        # Employees on leave today
        on_leave_today = LeaveRequest.objects.filter(
            start_date__lte=today, end_date__gte=today, status="approved"
        ).count()

        # Pending leave requests
        pending_leave_requests = LeaveRequest.objects.filter(status__iexact="pending").count()

        # Attendance requests pending approval
        attendance_requests = AttendanceRequest.objects.filter(status__iexact="pending").count()

        # Leave cancellations requested
        leave_cancellations = LeaveRequest.objects.filter(status__iexact="cancellation_requested").count()

        # ✅ Attendance statistics for the particular day
        present_today = Attendance.objects.filter(date=today, status="present").count()
        absent_today = Attendance.objects.filter(date=today, status="absent").count()
        late_today = Attendance.objects.filter(date=today, status="late").count()

        return Response({
            "total_employees": total_employees,
            "on_leave_today": on_leave_today,
            "leave_requests": pending_leave_requests,  # Changed from pending_leave_requests
            "attendance_request": attendance_requests, # Changed to match frontend
            "leave_cancellations": leave_cancellations,
            "present": present_today,  # Flattened from attendance_statistics
            "absent": absent_today,    # Flattened from attendance_statistics
            "late": late_today         # Flattened from attendance_statistics
        },status=200)

##################  HR employee view    ##########################

class EmployeeDetailView(generics.ListAPIView):
    authentication_classes = [JWTAuthentication]
    queryset = Employee.objects.filter(Q(user__role="Employee") | Q(user__role="employee"))
    serializer_class = EmployeeListSerializer
    permission_classes = [IsAuthenticated]

#################   HR employee manual attendance entry ####################

class ManualAttendanceView(generics.CreateAPIView):
    queryset = Attendance.objects.all()
    serializer_class = ManualAttendanceSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def create(self, request, *args, **kwargs):
        """Handles manual attendance creation."""
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Attendance recorded successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

########### hr employee add ###################

class EmployeeCreateView(generics.CreateAPIView):
    queryset = Employee.objects.all()
    serializer_class = EmployeeAddSerializer

    # def post(self, request, *args, **kwargs):
    #     serializer = self.get_serializer(data=request.data)
    #     if serializer.is_valid():
    #         employee = serializer.save()
    #         return Response({"message": "Employee created successfully", "id": employee.id}, status=status.HTTP_201_CREATED)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#########   hr requests leave for employee    #####################

class LeaveRequestCreateView(generics.CreateAPIView):
    queryset = LeaveRequest.objects.all()
    serializer_class = HRLeaveRequestSerializer
    permission_classes = [IsAuthenticated] 
    authentication_classes = [JWTAuthentication] 

############    HR self portal  #####################

