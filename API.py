from fastapi import FastAPI, HTTPException, status
import uvicorn
from SecureAPI import Agent
import CONSTANTS  # type: ignore
from pydantic import BaseModel, ValidationError
from typing import List, Dict, Any
import pandas as pd
import json,ast

app = FastAPI()

"""
Use the Below Command:
http POST http://127.0.0.1:8000/pii id=1 itemName="Item" data="data" tags=["tag"] pii:=True
http POST http://127.0.0.1:8000/pii Category="Dummy" PII="[{'Item Name':'Dummy Item Name','Data':'New Item'},{'Item Name':'Dummy Item2', 'Data':'Dummy Data'}]" Type="TypePII"

http GET http://127.0.0.1:8000/pii
the command is still not fully functional
"""

class PIIItem(BaseModel):
    Category: str
    PII: List[Dict[str, Any]]
    Type: str

class PII(BaseModel):
    items: List[PIIItem]

class PIIRow(BaseModel):
    Category: str
    PII: str
    Type: str



def convert_dataframe_to_pii_items(df: pd.DataFrame) -> List[Dict[str, Any]]:
    items = df.to_dict(orient='records')
    for item in items:
        if isinstance(item['PII'], str):
            # Deserialize JSON string to list of dictionaries
            try:
                item['PII'] = json.loads(item['PII'])
            except json.JSONDecodeError as e:
                print("JSON Decode Error:", e)
                item['PII'] = []
    return items

file_name = CONSTANTS.AWS_FILE
s3 = CONSTANTS.AWS_S3
agent = Agent(s3=s3, file_name=file_name)

pii_data_df = agent.get_all_data()
pii_data = convert_dataframe_to_pii_items(pii_data_df)

@app.get("/pii", response_model=PII)
def get_all_pii():
    try:
        # Validate the converted data against the PII model
        pii_items = [PIIItem(**item) for item in pii_data]
        return {"items": pii_items}
    except ValidationError as e:
        print("Validation Error:", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.get("/pii/{category}", response_model=List[PIIItem])
def get_category_pii(category: str):
    category_data = pii_data_df[pii_data_df['Category'] == category]
    category_pii_items = convert_dataframe_to_pii_items(category_data)
    try:
        # Validate the converted data against the PII model
        pii_items = [PIIItem(**item) for item in category_pii_items]
        return pii_items
    except ValidationError as e:
        print("Validation Error:", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@app.post('/pii', response_model=PIIRow, status_code=status.HTTP_201_CREATED)
def add_pii_item(item: PIIRow):
    try:
        # item.PII = ast.literal_eval(item.PII)
        print('Received Data', item)
        agent.update_all_data(item.model_dump())
        return item
    
    except Exception as e:
        print("Error adding data:", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
