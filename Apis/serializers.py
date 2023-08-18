from rest_framework import serializers
from .models import *

class UserModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = '__all__'

class ListProblemViewSerializer(serializers.ModelSerializer):
    id = serializers.ReadOnlyField()
    tags = serializers.SerializerMethodField()
    class Meta:
        model = ProblemModel
        fields = ('id', 'title', 'difficulty', 'acceptedSubmissions', 'totalSubmissions', 'tags')

    def get_tags(self, obj):
        tags = obj.tags.all()
        tag_names = [tag.name for tag in tags]
        return tag_names

class ListSubmissionsViewSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()
    problem = serializers.SerializerMethodField()

    class Meta:
        model = SubmissionModel
        fields = '__all__'
    
    def get_user(self, obj):
        return obj.user.username
    
    def get_problem(self, obj):
        return {
            'id': obj.problem.id,
            'title': obj.problem.title
        }

class SubmissionsOfAProblemSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubmissionModel
        fields = ('time', 'verdict', 'code')

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