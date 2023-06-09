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
import docker
import tarfile
from pathlib import Path
from django.core.files import File
import bcrypt

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv()

def authenticate(recievedJWT):
    decodedJWT=None
    try:
        decodedJWT = jwt.decode(recievedJWT, os.getenv('SECRET_KEY'), algorithms=['HS256'])
    except:
        return {"message": "Token is Invalid!", "status": status.HTTP_400_BAD_REQUEST}
    
    token = decodedJWT['token']
    user = UserModel.objects.filter(token=token).first()
    if user:
        return {"user": user, "status": status.HTTP_200_OK}
    else:
        return {"message": "User is Invalid!", "status": status.HTTP_404_NOT_FOUND}

def hash_password(password):
    # Generate a salt
    salt = bcrypt.gensalt()

    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    # Return the hashed password as a string
    return hashed_password.decode('utf-8')

def verify_password(password, hashed_password):
    # Verify the password
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def compareFiles(p1, p2):
    f1 = open(p1, "r")  
    f2 = open(p2, "r")  
  
    i = 0
    verdict = True

    file1 = f1.read().split("\n")
    file2 = f2.read().split("\n")
    lines1 = len(file1)
    lines2 = len(file2)
    lines = min(lines1, lines2) 
    
    while i<lines:
        l1 = file1[i]
        l2 = file2[i]
        if l1 != l2:
            verdict = False
            break
        i+=1  
            
        
    # closing files
    f1.close()                                       
    f2.close()
    
    return verdict

def create_container():
    # Docker client initialization
    client = docker.from_env()

    # Pull the gcc image
    client.images.pull('gcc')

    # Create a new container
    container = client.containers.create(
        'gcc',  # Image name
        'tail -f /dev/null',  # Command to keep the container running
        detach=True,  # Run container in the background
    )

    # Start the container
    container.start()

    return container

def copy_file(container, file):
    os.chdir(os.path.dirname(file))
    srcname = os.path.basename(file)
    tar = tarfile.open(file + '.tar', mode='w')
    try:
        tar.add(srcname)
    finally:
        tar.close()

    data = open(file + '.tar', 'rb').read()
    container.put_archive("/", data)
    os.remove(file+'.tar')

def execute_cpp(container, code_file, input_file, output_file):
    # Compile and run the C++ code
    cmd_compile = f"g++ {code_file} -o /output"
    cmd_run = f"/output < {input_file} > /output.txt"
    exec_cmd = f"bash -c '{cmd_compile} && {cmd_run}'"
    exec_code, output = container.exec_run(exec_cmd)

    output_data = container.exec_run("cat /output.txt")
    output_string = output_data.output.decode().strip()

    with open(output_file, 'w') as dest_file:
        dest_file.write(output_string)

class AuthenticateRoute(APIView):
    def post(self, request):
        recievedToken = request.data['token']
        if not recievedToken:
            return Response({"message": "Token not found!", "status": status.HTTP_404_NOT_FOUND})
        
        res = authenticate(recievedToken)

        if res["status"] == status.HTTP_404_NOT_FOUND:
            return Response(res)
        
        obj = {
            "status": res["status"],
            "name": res["user"].name,
            "email": res["user"].email,
            "profilePic": res["user"].profilePic
        }
        return Response(obj)

class LoginView(APIView):
    def post(self, request):
        recievedJWT = request.data['jwtToken']
        googleObj = None
        try:
            googleObj = gjwt.decode(recievedJWT, verify=False)
        except:
            return Response({"message":"Invalid JWT!", "status": status.HTTP_404_NOT_FOUND})
        
        userToken = str(uuid4())
        found = UserModel.objects.filter(email=googleObj['email']).first()
        user = found

        if not found:
            user = UserModel(email=googleObj['email'], name=googleObj['name'], profilePic=googleObj['picture'], token=userToken)
        else:
            user.token = userToken
        
        user.save()

        payload = {
                    "token": userToken
                  }
        jwtToken = jwt.encode(payload, os.getenv('SECRET_KEY'), algorithm='HS256')

        return Response({"jwtToken": jwtToken, "name": user.name, "email": user.email, "profilePic": user.profilePic, "status": status.HTTP_200_OK})

class LoginWithPassword(APIView):
    def post(self, request):
        email = request.data["email"]
        password = request.data["password"]
        
        user = UserModel.objects.filter(email=email).first()

        if not user:
            return Response({"message": "This email is not registered! Login with google to register yourself.", "status": status.HTTP_404_NOT_FOUND})

        if not user.hashedPassword:
            return Response({"message": "Login with google to add your password!", "status": status.HTTP_400_BAD_REQUEST})
        
        verified = verify_password(password, user.hashedPassword)

        if verified:
            userToken = str(uuid4())
            user.token = userToken
            user.save()

            payload = {
                    "token": userToken
                    }
            jwtToken = jwt.encode(payload, os.getenv('SECRET_KEY'), algorithm='HS256')
            return Response({"jwtToken": jwtToken, "name": user.name, "email": user.email, "profilePic": user.profilePic, "status": status.HTTP_200_OK})
        else:
            return Response({"message": "Password is wrong!", "status": status.HTTP_400_BAD_REQUEST})

class ChangeThePassword(APIView):
    def post(self, request):
        password = request.data["password"]
        recievedJWT = request.data['jwtToken']

        authentication = authenticate(recievedJWT=recievedJWT)
        if authentication['status'] != status.HTTP_200_OK:
            return Response(authentication)
        
        user = authentication["user"]
        hashedPassword = hash_password(password)
        user.hashedPassword = hashedPassword
        user.save()

        return Response({"message": "Password is changed!", "status": status.HTTP_200_OK})        
        


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

        ser_data = UserModelSerializer(user)
        return Response({"userDetails": ser_data.data, "status": status.HTTP_200_OK})

class CreateProblemView(APIView): 
    #Later Output file should be generated by evaluation server 
    def post(self, request):
        recievedJWT = request.data['jwtToken']
        response = authenticate(recievedJWT=recievedJWT)

        if response['status'] == status.HTTP_404_NOT_FOUND or response['user'].isAdmin == False:
            return Response({"message" : "User is Invalid!", "status": status.HTTP_404_NOT_FOUND})

        data = request.data
        files = request.FILES

        problemStatement = files["problemStatement"]
        hiddenTestCases = files["hiddenTestCases"]
        correctSolution = files["correctSolution"]
        correctOutput = files["correctOutput"]

        newProblem = ProblemModel(title=data["title"], problemStatement=problemStatement, visibleTestCases=data["visibleTestCases"],
                                  hiddenTestCases=hiddenTestCases, correctSolution=correctSolution, correctOutput=correctOutput,
                                  difficulty=data["difficulty"])
        newProblem.save()

        tagslist = data["tags"].split(", ")
        tagsQueryset = TagModel.objects.all()

        for tag in tagslist:
            found = tagsQueryset.filter(name=tag).first()
            y = found
            if(not found):
                y = TagModel(name=tag)
                y.save()
            else:
                y = found

            newProblem.tags.add(y)

        newProblem.save()
        return Response({"QuestionId": newProblem.id, "status": status.HTTP_200_OK})

class GetLeaderBoardView(APIView):
    def get(self, request):
        try:
            users = UserModel.objects.all()
            ser_data = GetLeaderBoardViewSerializer(users, many=True)

            return Response({"response": ser_data.data, "status": status.HTTP_200_OK})
        
        except:
            return Response({"message": "Unable to get the leaderboard!", "status": status.HTTP_400_BAD_REQUEST})

class ListProblemsView(APIView):
    def get(self, request):
        try:
            problems = ProblemModel.objects.all()
            ser_data = ListProblemViewSerializer(problems, many=True)
            
            return Response({"problems": ser_data.data, "status": status.HTTP_200_OK})
        
        except:
            return Response({"message": "Unable to get the Problems!", "status": status.HTTP_400_BAD_REQUEST})
    
class ListSubmissionsView(APIView):
    def post(self, request):
        recievedJWT = request.data['jwtToken']
        response = authenticate(recievedJWT=recievedJWT)

        if response['status'] == status.HTTP_404_NOT_FOUND:
            return Response({"message" : "User is Invalid!", "status": status.HTTP_404_NOT_FOUND})

        user = response['user']

        submissions = SubmissionModel.objects.filter(user__email = user.email).all()
        ser_data = ListSubmissionsViewSerializer(submissions, many=True)

        return Response({"submissions": ser_data.data, "status": status.HTTP_200_OK})
    
class ListTagsView(APIView):
    def get(self, request):
        try:
            availableTags = TagModel.objects.all()
            ser_data = TagModelSerializer(availableTags, many=True)
            return Response({"tags": ser_data.data, "status": status.HTTP_200_OK})
        except:
            return Response({"message": "Unable to get the Filter Tags!", "status": status.HTTP_400_BAD_REQUEST})
    
class ShowProblemView(APIView):
    def get(self, request):
        recievedJWT = request.data['jwtToken']
        response = authenticate(recievedJWT=recievedJWT)

        if response['status'] == status.HTTP_404_NOT_FOUND:
            return Response({"message" : "User is Invalid!", "status": status.HTTP_404_NOT_FOUND})

        questionId = request.data["questionId"]
        problem = ProblemModel.objects.filter(id=questionId).first()

        if(not problem):
            return Response({"status": status.HTTP_404_NOT_FOUND})

        ser_data = ShowProblemViewSerializer(problem)
        return Response({"response": ser_data.data, "status": status.HTTP_200_OK})

class SubmitProblemView(APIView):
    def post(self, request):
        recievedJWT = request.data['jwtToken']
        response = authenticate(recievedJWT=recievedJWT)

        if response['status'] == status.HTTP_404_NOT_FOUND:
            return Response({"message" : "User is Invalid!", "status": status.HTTP_404_NOT_FOUND})

        submissionFile = request.FILES["code"]
        questionId = request.data["questionId"]
        user = response['user']
        problem = ProblemModel.objects.filter(id=questionId).first()

        if not problem:
            return Response({"message" : "Problem ID is Invalid!", "status": status.HTTP_404_NOT_FOUND})

        submissionObj = SubmissionModel(code=submissionFile, user = user, problem = problem)
        submissionObj.save()

        emptyFilePath = f"{BASE_DIR}/Uploads/emptyFile.txt"
        print(emptyFilePath)
        with open(emptyFilePath, 'w') as file:
            pass

        with open(emptyFilePath, 'rb') as file_obj:
            submissionObj.outputs.save("new_file.txt", File(file_obj))

        submissionObj.save()

        inputs = problem.hiddenTestCases
        correctOutputs = problem.correctOutput

        code_path = submissionObj.code.path
        inputs_path = inputs.path
        outputs_path = submissionObj.outputs.path

        container = create_container()

        # Copy the code file to the container
        copy_file(container, code_path)
        copy_file(container, inputs_path)

        # Execute the code and capture the output
        execute_cpp(container, f'/{submissionObj.code.name.split("/")[1]}', f'/{inputs.name.split("/")[1]}', outputs_path)

        # Cleanup - stop and remove the container
        container.stop()
        container.remove()

        verdict = compareFiles(submissionObj.outputs.path, correctOutputs.path)

        problem.totalSubmissions += 1
        user.totalSubmissions += 1

        if verdict:
            problem.acceptedSubmissions += 1
            user.acceptedSubmissions += 1
        
        user.save()
        problem.save()

        return Response({"verdict": verdict, "message": "Successful submission!", "status": status.HTTP_200_OK})
    
class DeleteSubmissionsView(APIView):
    def post(self, request):
        recievedJWT = request.data['jwtToken']
        response = authenticate(recievedJWT=recievedJWT)

        if response['status'] == status.HTTP_404_NOT_FOUND or response['user'].isAdmin == False:
            return Response({"message" : "User is Invalid!", "status": status.HTTP_404_NOT_FOUND})
        
        submissionsToBeDeleted = request.data['submissionsToBeDeleted']

        for submissionId in submissionsToBeDeleted:
            submissionsList = SubmissionModel.objects.filter(id=submissionId)
            if not submissionsList.first():
                pass

            submission = submissionsList.first()
            codePath = submission.code.path
            outputsPath = submission.outputs.path

            os.remove(codePath)
            os.remove(outputsPath)

            submission.delete()
        
        return Response({"message":"Selected submissions are deleted!", "status": status.HTTP_200_OK})
