from django.contrib import admin
from .models import *
# Register your models here.

admin.site.register(UserModel)
admin.site.register(TagModel)
admin.site.register(ProblemModel)
admin.site.register(SubmissionModel)
admin.site.register(ProblemIdModel)
