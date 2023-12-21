import rsa
import uuid
import requests
import idea

(publicKey, privateKey) = rsa.newkeys(1024)
my_id = uuid.uuid4()

login_url = "http://localhost:8000/login"
getfile_url = "http://localhost:8000/getfile"

login_data = {
    "user_id": str(my_id),
    'public_key': publicKey.save_pkcs1().decode("utf-8")
}

login_response = requests.get(login_url, json=login_data)

login_response_data = login_response.json()
encoded_key = eval(login_response_data["encoded_key"])
idea_key = rsa.decrypt(encoded_key, privateKey).decode('utf-8')

files = login_response_data["files"]

while True:
    for index, item in enumerate(files, start=1):
        print(f"{index} - {item}")
    print("0 - break")
    print("Enter a index: ")

    user_input = int(input())
    if user_input == 0:
        break

    file_name = files[user_input - 1]
    getfile_data = {
        "user_id": str(my_id),
        'file_name': file_name
    }
    getfile_response = requests.get(getfile_url, json=getfile_data)
    getfile_response_data = getfile_response.json()
    encrypted_content = getfile_response_data["encrypted_content"]
    result_content = idea.encode_decode(data=encrypted_content, key=int(idea_key))
    print("_"*20)
    print(f"{file_name}: {result_content}")
    print("_" * 20)
