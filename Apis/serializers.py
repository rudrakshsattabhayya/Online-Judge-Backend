from rest_framework import serializers
from .models import *

class UserModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = '__all__'

class ListProblemViewSerializer(serializers.ModelSerializer):
    id = serializers.ReadOnlyField()
    class Meta:
        model = ProblemModel
        fields = ('id', 'title', 'difficulty', 'acceptedSubmissions', 'totalSubmissions')

class ListSubmissionsViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubmissionModel
        fields = '__all__'

class TagModelSerializers(serializers.ModelSerializer):
    class Meta:
        model = TagModel
        fields = '__all__'