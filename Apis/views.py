from django.shortcuts import render
from rest_framework.views import APIView
from .models import *
from .serializers import *
import jwt
import os
from rest_framework import status
from dotenv import load_dotenv
from rest_framework.response import Response
from google.auth import crypt
from google.auth import jwt as gjwt
from uuid import uuid4

load_dotenv()

def authenticate(recievedJWT):
    decodedJWT = jwt.decode(recievedJWT, os.getenv('SECRET_KEY'), algorithms=['HS256'])
    userId = decodedJWT['userId']
    token = decodedJWT['token']
    user = UserModel.objects.filter(token=token).first()
    if user:
        return {"user": user, "status": status.HTTP_200_OK}
    else:
        return {"status": status.HTTP_404_NOT_FOUND}

class LoginView(APIView):
    def post(self, request):
        recievedJWT = request.data['jwtToken']
        googleObj = gjwt.decode(recievedJWT, verify=False)

        if not googleObj:
            return Response("Invalid JWT!", status.HTTP_404_NOT_FOUND)
        
        userToken = str(uuid4())
        found = UserModel.objects.filter(email=googleObj['email']).first()
        user = found

        if not found:
            user = UserModel(email=googleObj['email'], name=googleObj['name'], profilePic=googleObj['picture'], token=userToken)
        else:
            user.token = userToken
        
        user.save()

        payload = {
                    "token": userToken,
                    "userId" : user.id
                  }
        jwtToken = jwt.encode(payload, os.getenv('SECRET_KEY'), algorithm='HS256')

        return Response({"jwtToken": jwtToken, "name": user.name, "email": user.email, "profilePic": user.profilePic, "status": status.HTTP_200_OK})

class ChangeUserNameView(APIView):
    def post(self, request):
        recievedJWT = request.data['jwtToken']
        response = authenticate(recievedJWT=recievedJWT)
        if response['status'] == status.HTTP_404_NOT_FOUND:
            return Response({"message" : "User is Invalid!", "status": status.HTTP_404_NOT_FOUND})
        
        newUserName = request.data["newUserName"]
        user = UserModel.objects.filter(email=response['user'].email).first()
        user.username = newUserName
        user.save()

        ser_data = UserModelSerializers(user)
        return Response({"userDetails": ser_data.data, "status": status.HTTP_200_OK})
    

