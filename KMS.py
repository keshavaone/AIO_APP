import boto3
import os
from dataclasses import dataclass
import base64
import pandas as pd
import CONSTANTS
from cryptography.fernet import Fernet



class KMS:
    def __init__(self):
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        self.kms = boto3.client('kms')
        self.data_path:str = CONSTANTS.AWS_FILE         
        
    def decrypt_my_key(self, key):
        response = self.kms.decrypt(CiphertextBlob=key)
        fernet_key = base64.urlsafe_b64encode(response['Plaintext'])
        self.cipher_suite = Fernet(fernet_key)
        return self.cipher_suite
    
    def create_new_key(self):
        self.data_path:str = self.file_name
        self.__df = pd.read_excel(self.data_path)
        self.key = self.generate_secure_key('AES_256')
        self.__key = self.key['Plaintext']
        self.storing_key = self.key['CiphertextBlob']
        self.cipher_suite = Fernet(base64.urlsafe_b64encode(self.__key))
        return self.cipher_suite,self.__df

    
    
    def generate_secure_key(self, key_spec):
        aws_key = os.getenv('AWS_KEY')
        assert aws_key != None
        self.__key_id = aws_key
        response = self.kms.generate_data_key(
            KeyId=self.__key_id,
            KeySpec=key_spec
        )
        return response
    

    def create_new_key(self):
        self.__df = pd.read_excel(self.data_path)
        self.key = self.generate_secure_key('AES_256')
        self.__key = self.key['Plaintext']
        self.storing_key = self.key['CiphertextBlob']
        self.cipher_suite = Fernet(base64.urlsafe_b64encode(self.__key))
        return self.cipher_suite

    def decrypt_data(self,item):
        return self.cipher_suite.decrypt(item).decode('utf-8')
   
    
  