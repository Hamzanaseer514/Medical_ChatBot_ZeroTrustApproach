from django.urls import path
from . import views

urlpatterns = [
    path('', views.home_view, name='home'),
    path('signup/', views.signup, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('upload/', views.upload_pdf, name='upload_pdf'),
    path('chat/', views.chat, name='chat'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('verify-login-otp/', views.verify_login_otp, name='verify_login_otp'),
]