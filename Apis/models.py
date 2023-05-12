from django.db import models
import uuid

class UserModel(models.Model):
    email = models.EmailField(max_length=50, default="email@email.com")
    name = models.CharField(max_length=50, default="name")
    username = models.CharField(max_length=20, default="username")
    profilePic = models.URLField(max_length=500, default="http://www.example.com")
    token = models.CharField(max_length=1000, default="")
    leaderBoardScore = models.IntegerField(default=0)
    totalSubmissions = models.IntegerField(default=0)
    acceptedSubmissions = models.IntegerField(default=0)

    def __str__(self):
        return self.email

class TagModel(models.Model):
    name = models.CharField(max_length=40, default="default")

    def __str__(self):
        return self.name

class ProblemModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=30)
    problemStatement = models.FileField(upload_to="problemStatements")
    visibleTestCases = models.CharField(max_length = 1000, null = True)
    HiddenTestCases = models.FileField(upload_to="testCases")
    correctSolution = models.FileField(upload_to="solutions")
    correctOutput = models.FileField(upload_to="correctOutputs")
    difficulty = models.IntegerField(default=1)
    acceptedSubmissions = models.IntegerField(default=0)
    totalSubmissions = models.IntegerField(default=0)
    tags = models.ManyToManyField(TagModel, related_name="problems", default="default")

    def __str__(self):
        return self.prob_name

class SubmissionModel(models.Model):
    code = models.FileField(upload_to="submissions")
    time = models.DateTimeField(auto_now_add=True)
    verdict = models.BooleanField(default=False)
    user = models.ForeignKey(UserModel, related_name="submissions", on_delete=models.CASCADE)
    problem = models.ForeignKey(ProblemModel, related_name="submissions", on_delete=models.CASCADE)

    def __str__(self):
        return self.user.name + " (" + self.problem.title + ")"