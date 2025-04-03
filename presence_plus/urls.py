from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import *

router = DefaultRouter()

router.register(r'leave-policy', LeavePolicyCreateView, basename="leave-policy")
router.register(r'leave-policies', LeavePolicyViewSet, basename='leave-policies')
router.register(r'leave-policy-update',LeavePolicyDetailView, basename='leave-update')
router.register(r'work-time-view',WorkTimePolicyDetailView, basename='work-time-view')
router.register(r'work-time-policies',WorkTimePolicyCreateListView, basename='work-time-policies')

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path("token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path('userview/', CreateUserView.as_view(), name='userview'),
    path("forgot-password/", ForgotPasswordView.as_view(), name="forgot-password"),
    path("reset-password/", ResetPasswordView.as_view(), name="reset-password"),
    path('editrole/',EditUserRoleView.as_view(),name='editrole'),
    path('hr-list/', HRListView.as_view(), name='hr_list'),
    path('delete/<int:hr_id>/', Delete.as_view(), name='delete'),
    path('admincount/',DashboardCountsView.as_view(), name='admincount'),
    path('admstat/',AttendanceStatsView.as_view(), name='admstat'),
    path("leave-requests/", LeaveRequestListView.as_view(), name="leave-requests"),
    path("leavecancellationview/",PendingLeaveCancellationRequestsView.as_view(), name='leavecancellationview'),
    path("policyleavetype/",LeaveTypeCreateView.as_view(), name="policyleavetype"),
    path("public-holidays/", PublicHolidayView.as_view(), name="public-holidays"),
    path('', include(router.urls)),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("hrleavecancel/<int:leave_id>/", LeaveCancellationApprovalView.as_view(), name="hrleavecancel"),
    path("hrdashboard/",HRDashboardView.as_view(), name="hrdashboard"),
    path("hrempview/",EmployeeDetailView.as_view(),name="hrempview"),
    path("hrmanualattend/",ManualAttendanceView.as_view(), name="hrmanualattend"),
    path("employee/<int:employee_id>/leave-balance/", EmployeeLeaveBalanceView.as_view(),name="employee-leave-balance"),
    path("hrleaverequestview/",PendingLeaveRequestsView.as_view(), name="hrleaverequestview"),
    path("hr/attendance-stats/", HRMonthlyAttendanceView.as_view(), name="hr-attendance-stats"),#hr self portal
    path("hrcommunity/",CommunityView.as_view(), name="hrcommunity"),
    path('hrdesignation/', DesignationListCreateView.as_view(), name='designation-list-create'),
    path("approve-reject-leave/<int:leave_id>/", ApproveRejectLeaveView.as_view(), name="approve_reject_leave"),
    path("approve-reject-cancellation/<int:leave_id>/", ApproveRejectCancellationView.as_view(), name="approve_reject_cancellation"),
    path("leave-history/", LeaveHistoryView.as_view(), name="leave_history"),
    path("employees/", EmployeeListView.as_view(), name="employee_list"),
    path("leave-types/dropdown/", LeaveTypeDropdownView.as_view(), name="leave_type_dropdown"),
    path("empview/", EmployeeDashboardView.as_view(), name="empview"),
    path("empleave/", LeaveRequestView.as_view(), name="empleave"),
    path('leave/cancel/<int:leave_id>/', LeaveCancellationRequestView.as_view(), name='leave-cancel-request'),
    path("empovertime/",OvertimeStatsView.as_view(), name="empovertime"),
    path("empoverstat/",OvertimeAssignmentView.as_view(),name="empoverstat"),
    path("empattendance/", AttendanceListView.as_view(), name="attendance-list"),
    path("empattendance/request/", AttendanceRequestView.as_view(), name="attendance-request"),
    path("empattendance/request/<int:pk>/approve/", AttendanceRequestApprovalView.as_view(), name="attendance-request-approve"),
    path("empshiftview/", EmployeeShiftView.as_view(), name="empshiftview"),
    path("empshiftroster/", ShiftRosterView.as_view(), name="empshiftroster"),
    path("empprofile/",EmployeeProfileView.as_view(), name="empprofile"),
    path("change-password/",ChangePasswordView.as_view(), name="change-password"),
    path("empleavebalance/",EmployeeLeaveBalanceView.as_view(), name="empleavebalance"),
    path("policy-view/",PolicyListView.as_view(), name="policyview"),
    path('leave-type/', LeaveTypeListView.as_view(), name='leave-types'),
    path('leavesummary/',LeaveBalanceSummaryView.as_view(), name='leavesummary'),
    path('empattendstat/',MonthlyAttendanceStatisticsView.as_view(), name='empattendstat'),
    path('working-hours/', WorkingHoursListCreateView.as_view(), name='working_hours'),
    path('assign-shift/', AssignShiftView.as_view(), name='assign_shift'),
    path('assignview/',AssignedShiftView.as_view(), name='assignview'),
    path('employee-shifts/', EmployeeShiftView.as_view(), name='employee_shifts'),
    path('employeedashboardshifts/', EmployeeDasboardShiftView.as_view(), name='employeedashboardshifts'),
    path('shift-colleagues/<str:date>/', ShiftColleaguesView.as_view(), name='shift_colleagues'),
    path('shift/colleagues/', ShiftColleaguesDashboardView.as_view(), name='shift-colleagues-today'),
    path('hrempleavecreate/',HRRequestLeaveView.as_view(), name='heempleavecreate'),
    path('leavenotification/',NotificationListView.as_view(), name='leavenotification'),
    path('overtimeoverview/',OvertimeSummaryView.as_view(), name='overtimeoverview'),
    path('overtimereport/',OvertimeSummaryDownloadView.as_view(), name='overtimereport'),
    path('employee/overtime/<int:employee_id>/',EmployeeOvertimeDetailView.as_view(), name='overtimeempview'),
    path('overtimeempassign/',FirstAssignOvertimeView.as_view(), name='overtimeempassign'),
    path('attendancedashboard/', HRAttendanceView.as_view(), name='attendancedashboard'),
    path('attendance/requests/', HRAttendanceRequestView.as_view(), name='pending-attendance-requests'),
    path('attendancereports/', GenerateReportView.as_view(), name='attendancereports'),
    path('employee/<int:employee_id>/attendance/', EmployeeAttendanceDetailView.as_view(), name='employee-attendance-detail'),
    path('attendance/add/<int:employee_id>/', AddAttendanceRecordView.as_view(), name='add-attendance'),
    path('empattendoverview/',EmployeeAttendanceDashDetailView.as_view(), name='empattendoverview'),
    path("adminattendance/",AdminAttendanceReportView.as_view(), name='adminattendance'),
    path("api/admin/attendance-report/download/",AdminAttendanceReportDownloadView.as_view(), name= 'attendance-report'),
]
urlpatterns += router.urls           