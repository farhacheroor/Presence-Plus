from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import *

router = DefaultRouter()
router.register(r'public-holidays', PublicHolidayViewSet)
#router.register(r'communities', CommunityViewSet)
router.register(r'leave-policy', LeavePolicyCreateView, basename="leave-policy")
router.register(r'leave-policies', LeavePolicyViewSet, basename='leave-policies')
router.register(r'leave-policy-update',LeavePolicyDetailView, basename='leave-update')
router.register(r'work-time-view',WorkTimePolicyDetailView, basename='work-time-view')
router.register(r'work-time-policies',WorkTimePolicyCreateListView, basename='work-time-policies')
router.register(r'leave-types', LeaveTypeViewSet, basename='leave-types')

router.register(r'working-hours', WorkingHoursViewSet)
router.register(r'shift-rosters', ShiftRosterViewSet)
router.register(r'employees', EmployeeViewSet)
router.register(r'employee-shifts', EmployeeShiftAssignmentViewSet)

urlpatterns = [
    ###############     Admin   #####################
    #path("leave-types/", LeaveTypeViewSet.as_view({"get": "list", "post": "create"}), name="leave-types"),
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
    path("leave-requests/<int:leave_id>/", ManageLeaveRequestView.as_view(), name="manage-leave"),
    path("leave-requests/<int:leave_id>/cancel/", ManageCancellationRequestView.as_view(), name="cancel-leave"),
    path('attendance-report/', AttendanceReportView.as_view(), name='attendance-report'),
    #path("leave-policy/create/", LeavePolicyCreateView.as_view(), name="leave-policy-create"),
    #path("leave-policy/<int:pk>/", LeavePolicyDetailView.as_view(), name="leave-policy-detail"),
    #path("work-time-policies/", WorkTimePolicyCreateListView.as_view(), name="work-time-policy-list-create"),
    #path("work-time-policies/<int:pk>/", WorkTimePolicyDetailView.as_view(), name="work-time-policy-detail"),
    path('', include(router.urls)),
    path("logout/", LogoutView.as_view(), name="logout"),
    ############### HR  ##########################
    path("hrleavecancel/", LeaveCancellationApprovalView.as_view(), name="hrleavecancel"),
    #path("hrshift/", AssignEmployeeShiftView.as_view(), name="hrshift"),
    path("hrdashboard/",HRDashboardView.as_view(), name="hrdashboard"),
    path("hrempview/",EmployeeDetailView.as_view(),name="hrempview"),
    path("hrmanualattend/",ManualAttendanceView.as_view(), name="hrmanualattend"),
    path("employee/<int:employee_id>/leave-balance/", EmployeeLeaveBalanceView.as_view(),name="employee-leave-balance"),
    path("employees/add/", EmployeeCreateView.as_view(), name="employee-add"), 
    path("request-leave/", LeaveRequestCreateView.as_view(), name="request-leave"),
    #################   Employee    ###############
    path("empview/", EmployeeDashboardView.as_view(), name="empview"),
    path("empleave/", LeaveRequestView.as_view(), name="empleave"),
    path("empleavecancellation/", LeaveCancellationRequestView.as_view(), name="empleavecancellation"),
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
    path("empleavebalancehistory/",LeaveHistoryView.as_view(), name="empleavebalancehistory"),
    path("policy-view/",PolicyListView.as_view(), name="policyview"),
    path('leave-type/', LeaveTypeListView.as_view(), name='leave-types'),
    path('leavesummary/',LeaveBalanceSummaryView.as_view(), name='leavesummary'),
    path('empattendstat/',MonthlyAttendanceStatisticsView.as_view(), name='empattendstat'),
]
urlpatterns += router.urls