from django.urls import path
from .views import *

urlpatterns = [
    path('login', LoginView.as_view()),
    path('change-username', ChangeUserNameView.as_view()),
    path('create-problem', CreateProblemView.as_view()),
]