from datetime import datetime, timedelta, timezone
from typing import Annotated, Union
import base64 
import jwt
from fastapi import Depends, FastAPI, HTTPException, status, Request, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel

import ultralytics
from ultralytics import YOLO
import cv2

from google.oauth2 import service_account
from google.cloud import datastore
from datetime import datetime, timedelta, timezone

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class UserLogin(BaseModel):
    username:str
    password:str

class ImageName(BaseModel):
    filename:str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)



def get_password_with_username(username):
    credentials = service_account.Credentials.from_service_account_file("secret-node-424009-k6-4dc19cc48467.json")
    client = datastore.Client(credentials=credentials, database="testbase", namespace="user", project="secret-node-424009-k6")
    query = client.query(kind="user")
    query = query.add_filter(filter=datastore.query.PropertyFilter("username", "=", username))
    results = list(query.fetch())


    if results:
        return True, results[0].get("password")
    else:
        return False, "user doenot exist"


@app.get("/")
def read_root():
    return "Hello World"


@app.post("/login")
async def login(userLogin: UserLogin):

    print(userLogin.username.strip(), userLogin.password.strip())

    if userLogin.username.strip() == "" or userLogin.password.strip() == "":
        return {"success":False, "message": "username or password cannot be empty"}

    userInDBstatus, password = get_password_with_username(userLogin.username)
    if userInDBstatus == False:
        return {"success":False, "message": "user doesnot exist"}
        
    try:
        user = verify_password(userLogin.password.strip(), password)
    except:
        print("ok")
        return {"success":False, "message": "incorrect password"}
                
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    exp_time = datetime.now(timezone.utc) + timedelta(minutes=15)
   

    payload = {"username": userLogin.username.strip(), "exp": exp_time}
    access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    
    return {"success": True, "token": {"access_token": access_token, "token_type": "bearer"}}
    
def verify_token(req: Request):
    token = req.headers["Authorization"]

    try:
        jwt.decode(token.split(" ")[-1], SECRET_KEY, algorithms=[ALGORITHM])
        print(jwt.decode(token.split(" ")[-1], SECRET_KEY, algorithms=[ALGORITHM]))
        return True
    except jwt.ExpiredSignatureError:
        print("has expired")
        return False
        
@app.get("/test")
async def home(authorized: bool = Depends(verify_token)):
    if authorized:
        return {"success": True, "detail": "Welcome home"}
    else:
        return {"success": False, "message": "token has expired"}

@app.post("/uploadfile")
def upload(file: UploadFile = File(...), authorized: bool = Depends(verify_token)):
    if authorized == False:
        return {"success": False, "message": "token has expired"}

    # print(file, file, )
    # try:
    #     contents = file.file.read()
    #     with open(file.filename, 'wb') as f:
    #         f.write(contents)
    # except Exception:
    #     return {"message": "There was an error uploading the file"}
    # finally:
    #     file.file.close()

    contents = file.file.read()
    with open("/tmp/"+file.filename, 'wb') as f:
        f.write(contents)
    file.file.close()
    return {"message": f"Successfully uploaded {file.filename}"}

        

@app.post("/inference")
def upload(file: ImageName):

    print(file.filename)

    



# @app.post("/inference")
# def inference(img: ImgData, current_user:Annotated[User, Depends(get_current_active_user)]):

#     base64_received = str.encode(img.image_data)
#     image_64_decode = base64.b64decode(base64_received)
#     image_result = open('/tmp/testk.jpg', 'wb') # create a writable image and write the decoding result
#     image_result.write(image_64_decode)

#     model = YOLO("model/yolov8n.pt")


#     results = model("/tmp/testk.jpg")  

#     cv2.imwrite("/tmp/pr.jpg", results[0].plot())


#     image = open('/tmp/pr.jpg', 'rb') #open binary file in read mode
#     image_read = image.read()
#     image_64_encode = base64.b64encode(image_read)
#     return_byte = image_64_encode.decode()
    
#     return {"success":True, "annotated_image_bytestring": return_byte}

    

