from fastapi import FastAPI
import uvicorn
from SecureAPI import Agent
import os

"""
Use the Below Command:
http POST http://127.0.0.1:8000/pii id=1 itemName="Item" data="data" tags=["tag"] pii:=True


the command is still not fully functional

"""
app = FastAPI()

file_name = os.getenv("AWS_FILE_NAME")
s3 = os.get_env("AWS_S3_BUCKET")
agent = Agent(s3=s3, file_name=file_name)


pii_data = agent.get_all_data()

@app.get("/pii")
def get_all_pii():
    return pii_data


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
