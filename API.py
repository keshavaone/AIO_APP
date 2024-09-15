from fastapi import FastAPI, HTTPException,status
import uvicorn
from SecureAPI import Agent
import ast
import CONSTANTS #type: ignore
from pydantic import BaseModel, Field, ValidationError
from typing import List, Dict, Any
import pandas as pd
import json


app = FastAPI()

"""
Use the Below Command:
http POST http://127.0.0.1:8000/pii id=1 itemName="Item" data="data" tags=["tag"] pii:=True


the command is still not fully functional

"""


class PIIItem(BaseModel):
    Category: str
    PII: List[Dict[str, Any]]
    Type: str

class PII(BaseModel):
    items: List[PIIItem]

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

@app.get("/pii/{category}")
def get_category_pii(category: str):
    data = pii_data_df[pii_data_df['Category']==category]
    return convert_dataframe_to_pii_items(data)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
