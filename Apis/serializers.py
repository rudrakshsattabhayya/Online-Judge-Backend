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
        exclude = ('outputs',)

class TagModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = TagModel
        fields = '__all__'

class ShowProblemViewSerializer(serializers.ModelSerializer):
    id = serializers.ReadOnlyField()
    tags = TagModelSerializer(many=True)
    class Meta:
        model = ProblemModel
        exclude = ('hiddenTestCases', 'correctSolution', 'correctOutput')

class GetLeaderBoardViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = ('username', 'leaderBoardScore', 'id')