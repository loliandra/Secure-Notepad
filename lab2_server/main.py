import uvicorn
import os
import idea
import rsa
from os.path import expanduser
from pydantic import BaseModel
from fastapi import FastAPI

app = FastAPI()
files = {}
users = {}

class LoginItem(BaseModel):
    public_key: str
    user_id: str

class GetFileItem(BaseModel):
    file_name: str
    user_id: str

@app.get("/login")
async def login(item: LoginItem):
    idea_key = idea.generate_key()
    str_idea_key = str(idea_key)
    rsa_key = rsa.PublicKey.load_pkcs1(item.public_key)
    # encoded_key = rsa.encode(idea_key, rsa_key)
    encoded_key = rsa.encrypt(str_idea_key.encode('utf-8'), rsa_key)
    users[item.user_id] = idea_key

    print(idea_key)
    byte_arr = bytearray(encoded_key)
    str_byte_arr = str(byte_arr)

    return {"encoded_key": str_byte_arr, "files": list(files.keys())}


@app.get("/getfile")
async def getfile(item: GetFileItem):
    file_content = files[item.file_name]
    idea_key = users[item.user_id]
    encrypted_content = idea.encode_decode(data=file_content, key=idea_key)
    return {"encrypted_content": encrypted_content}

def read_files():
    path = "~/unik/kb/lab2_server/Files"
    expanded_path = expanduser(path)
    dir_list = os.listdir(expanded_path)
    for file in dir_list:
        path = os.path.join(expanded_path, file)
        read_file(path, file)

def read_file(path, filename):
    file = open(path, "r")
    content = file.read()
    files[filename] = content

if __name__ == "__main__":
    read_files()
    uvicorn.run(app, host="127.0.0.1", port=8000)

