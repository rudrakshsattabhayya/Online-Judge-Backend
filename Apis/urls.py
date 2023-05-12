from django.urls import path
from .views import *

urlpatterns = [
    path('login', LoginView.as_view()),
    path('change-username', ChangeUserNameView.as_view()),
    path('create-problem', CreateProblemView.as_view()),
    path('list-problems', ListProblemsView.as_view()),
    path('list-submissions', ListSubmissionsView.as_view()),
    path('list-tags', ListTagsView.as_view()),
    path('show-problem', ShowProblemView.as_view()),
    path('get-leaderboard', GetLeaderBoardView.as_view()),
    path('submit-problem', SubmitProblemView.as_view()),
]