from django.shortcuts import render
from rest_framework.views import APIView
from .models import *
import jwt
import os
from rest_framework import status
from dotenv import load_dotenv
from rest_framework.response import Response
from google.auth import crypt
from google.auth import jwt as gjwt

load_dotenv()


    

