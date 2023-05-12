from django.urls import path
from .views import *

urlpatterns = [
    path('login', LoginView.as_view()),
    path('change-username', ChangeUserNameView.as_view()),
    path('create-problem', CreateProblemView.as_view()),
    path('list-problems', ListProblemsView.as_view()),
    path('list-submissions', ListSubmissionsView.as_view()),
    path('list-tags', ListTagsView.as_view()),
]