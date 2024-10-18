from fastapi import FastAPI, HTTPException, status
import uvicorn
from fastapi.responses import JSONResponse
from SecureAPI import Agent
import CONSTANTS  # type: ignore
from pydantic import BaseModel, ValidationError
from typing import List, Dict, Any
import pandas as pd
import json,ast

app = FastAPI()

"""
Use the Below Command:
http POST http://127.0.0.1:8000/pii Category="Dummy" PII="[{'Item Name':'Dummy Item Name','Data':'New Item'},{'Item Name':'Dummy Item2', 'Data':'Dummy Data'}]" Type="TypePII"
http PATCH http://127.0.0.1:8000/pii Category="Dummy" PII="[{'Item Name':'Dummy Item Name','Data':'New Item'},{'Item Name':'Dummy Item2', 'Data':'Dummy Data'}]" Type="TypePII"
http GET http://127.0.0.1:8000/pii
the command is still not fully functional
"""

file_name = CONSTANTS.AWS_FILE
s3 = CONSTANTS.AWS_S3
agent = Agent(s3=s3, file_name=file_name)

"""
 CREATE APIs with Security, Authenticity and Authority.
 1. API for CREATE, READ, UPDATE and DELETE.
 2. API for CLOUD CONNECTION, ENCRYPTION AND DECRYPTION.
 3. API for Data Security and Authenticity.
 4. API for Logs Monitoring.
 5. API for Backups.
 """

# Define a global variable to keep track of total API calls
global totalAPICalls
totalAPICalls = 0

def gather_logs(func):
    def wrapper(*args, **kwargs):
        global totalAPICalls  # Declare totalAPICalls as global to modify its value
        try:
            totalAPICalls += 1  # Increment the global totalAPICalls
            print(f"Total API Calls: {totalAPICalls}")
            result = func(*args, **kwargs)  # Call the original function
            return result  # Return the result of the function call
        except Exception as e:
            raise e  # Raise any exceptions encountered
    return wrapper  # Return the wrapper function

@gather_logs
def process_data(item,operation):
    
    try:
        match operation:
            case 'insert':
                response = agent.insert_new_data(item)
            case 'update':
                response = agent.update_one_data(item)
            case 'delete':
                response = agent.delete_one_data(item)
            case _:
                raise ValueError("Invalid operation")
        
        if response:
            return {"message": f"PII data {operation}ed successfully","response":response}
        else:
            return {"message": f"Failed to {operation} PII data. Reason: {response}"}
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

#1. API for CREATE
@app.post("/pii")
def insert_pii_item(item: Dict[str, Any]):
    return process_data(item, 'insert')


@app.patch("/pii")
def update_pii_item(item: Dict[str, Any]):
    return process_data(item, 'update')


@app.delete("/pii")
def delete_pii_item(item: Dict[str, Any]):
    return process_data(item, 'delete')

@gather_logs
@app.get("/pii")
def get_pii_data():
    print(f"Total API Calls: {totalAPICalls}")
    data = agent.get_all_data()
    data.drop('_id',axis=1,inplace=True)
    data = data.to_dict(orient='records')
    return data


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
