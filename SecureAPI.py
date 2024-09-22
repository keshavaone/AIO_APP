import boto3 # type: ignore
from cryptography.fernet import Fernet # type: ignore
from dataclasses import dataclass,field
import base64,os,io,time,json,time
import pandas as pd #type:ignore
import atexit
import ast, datetime
import CONSTANTS
from pymongo import MongoClient # type: ignore
from pymongo.server_api import ServerApi # type: ignore

@dataclass(eq=False, repr=False, order=False)
class Agent:
    s3:str
    file_name:str
    output_path:str = 'secrets.txt'
    input_path:str = 'ReQuest.txt'
    encrypt_path:str = 'encrypted_text.txt'
    stored_file_names:list[str] = field(default_factory=list)
    

    def get_current_time(self):
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    

    def __post_init__(self):
        self.status = {'Waking Up Mr.Agent...': self.get_current_time()}
        print('INIT - Waking Up Mr.Agent...',end='\r')
        
        # Create a MongoClient to the running MongoDB instance
        client = MongoClient('mongodb://localhost:27017/',server_api=ServerApi('1'))

        # Access the database (MyPII) and collection (PIIData)
        db = client['MyPII']
        self.collection = db['PIIData']
        
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        self.kms_client = boto3.client('kms')
        self.data_path:str = self.file_name
        aws_key = os.getenv('AWS_KEY')
        assert aws_key != None
        self.__key_id = aws_key
        self.status['Agent Ready'] = self.get_current_time()
        self.fetch_my_key()
        # self.process_file(mode='w',data='Success',file_path='status.txt')
        atexit.register(self.end_work)
    
    def create_new_key(self):
        self.__df = pd.read_excel(self.data_path)
        self.key = self.generate_secure_key('AES_256')
        self.__key = self.key['Plaintext']
        self.storing_key = self.key['CiphertextBlob']
        self.cipher_suite = Fernet(base64.urlsafe_b64encode(self.__key))

    def fetch_my_key(self):
        self.status['Agent Requested to Perform Connection to Cloud...'] = self.get_current_time()
        # self.__df = self.read_excel_from_s3(self.s3,self.file_name)
        data = self.collection.find()
        df = pd.DataFrame(data)
        self.__df = df.drop('_id',axis=1)
        grouped = self.__df.groupby('Category')['Type'].apply(list).reset_index()
        self.status['Connection to Cloud - Successful'] = self.get_current_time()
        JsonData = {}
        
        for item in grouped.values.tolist():
            keys = item[0].split('.')
            if len(keys) == 1:
                # If there's only one key, add the values as a list
                JsonData[keys[0]] = item[1]
            else:
                # If there are multiple keys, create a nested dictionary and append it to the list
                if keys[0] not in JsonData:
                    JsonData[keys[0]] = []
                JsonData[keys[0]].append({keys[1]: item[1]})

        JsonData = json.dumps(JsonData)
        self.__encoded_key = self.filter_from_db('KeyID')
        response = self.kms_client.decrypt(CiphertextBlob=self.__encoded_key)
        fernet_key = base64.urlsafe_b64encode(response['Plaintext'])
        self.cipher_suite = Fernet(fernet_key)
        return 
    
    def generate_secure_key(self, key_spec):
        response = self.kms_client.generate_data_key(
            KeyId=self.__key_id,
            KeySpec=key_spec
        )
        return response

    
    def filter_from_db(self,item_name = None,download_request = False):
        if download_request:
            return 0
        elif item_name is not None:
            data = base64.b64decode(self.__df[self.__df['Type'] == item_name]['PII'].values[0])
            return data
    
    
    def process_request(self):
        input_request = self.process_file('r')
        if input_request == 'Download':
            self.download_excel()
            output = self.data_path  
        elif input_request == 'Re-Encrypt':
            self.upload_securely(self.file_name)
            output = 'Success'
        else:
            data = self.filter_from_db(input_request)
            pre_output = self.decrypt_data(data)
            post_output = pd.DataFrame(data=pd.read_json(io.StringIO(pre_output), orient='records'))
            output = post_output.set_index('Item Name').to_json()
        print('Processed: ',input_request)
        os.remove(self.input_path)
        # return self.process_file(mode='w',data=output,file_path=self.output_path)
    
    
    def read_excel_from_file(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        df = pd.read_excel(file_path)
        return df

    
    def read_excel_from_s3(self,bucket_name, object_key):
        s3 = boto3.client('s3')
        try:
            response = s3.get_object(Bucket=bucket_name, Key=object_key)
            excel_data = response['Body'].read()
            df = pd.read_excel(io.BytesIO(excel_data))
            return df
        except Exception as e:
            print(f"Error reading Excel file from S3: {e}")
            return None
    
    def refresh_data(self):
        return pd.DataFrame(self.collection.find())
    
    def decrypt_data(self,item):
        return self.cipher_suite.decrypt(item).decode('utf-8')
    
    def get_all_data(self):
        df = self.refresh_data()
        if '_id' in df:
            df.drop('_id',axis=1,inplace=True)
        
        for i in df.index:
            if df.loc[i, 'Type'] == 'KeyID':
                pass
            else:
                df.loc[i, 'PII'] = self.decrypt_data(self.filter_from_db(df.loc[i, 'Type']))
                # print(df.loc[i,'PII'])
        return df
    
    def update_all_data(self,item):
        response = self.collection.insert_one({'Category':item['Category'], 'Type':item['Type'], 'PII': base64.b64encode(self.cipher_suite.encrypt(item['PII'].encode('utf-8'))).decode('utf-8')})
        print(response.acknowledged)
        return response.acknowledged
    
    def update_one_data(self,item):
        response = self.collection.update_one({'Category':item['Category'], 'Type':item['Type']}, {'$set': {'PII': base64.b64encode(self.cipher_suite.encrypt(item['PII'].encode('utf-8'))).decode('utf-8')}})
        print(response.modified_count, response.acknowledged)
        return response.modified_count, response.acknowledged

    def download_excel(self):
        df = self.get_all_data()
        df.to_excel(self.data_path, index=False)
        print('Excel File Downloaded Successfully')
        return True
    
    
    # for Desktop Application
    def get_options_to_choose(self):
        df = self.get_all_data()
        return list(set(df['Category'].to_list()))

    # for Desktop Application
    def get_sub_options_to_choose(self, category):
        df = self.get_all_data()
        df = df[df['Category'] == category]
        self.chosen_one = category
        return list(set(df['Type'].to_list()))

    # for Desktop Application
    def get_final_output(self,type):
        df = self.get_all_data()
        df = df[df['Category'] == self.chosen_one]
        df = df[df['Type'] == type]
        try:
            return ast.literal_eval(df['PII'].iloc[0])
        except:
            try:
                return ast.literal_eval(df['PII'].iloc[0].replace('\n', ' THIS_IS_NEW_LINE '))  
            except:
                return df['PII'].iloc[0]
    
    # for Source Code
    def perform_specific_output(self):
        # Fetch all data
        df = self.get_all_data()
        
        # Get unique categories
        categories = list(set(df['Category'].to_list()))
        for i, category in enumerate(categories):
            print(i, ':', category)
        
        # Input for selecting a category
        input_category = int(input('Enter the category number: '))
        selected_category = categories[input_category]
        
        # Filter dataframe based on selected category
        filtered_df = df[df['Category'] == selected_category]
        
        # Get unique types within the filtered category
        types = list(set(filtered_df['Type'].to_list()))
        for i, type_name in enumerate(types):
            print(i, ':', type_name)
        
        # Input for selecting a type
        input_type = int(input('Enter the type number: '))
        selected_type = types[input_type]
        
        # Further filter dataframe based on selected type
        filtered_df = filtered_df[filtered_df['Type'] == selected_type]
        
        # Extract and parse the PII data
        data_item = filtered_df['PII'].iloc[0].replace('\n',' THIS_IS_NEW_LINE ')
        data = ast.literal_eval(data_item)
    
        # Print items in the PII data
        for item in data:
            try:
                print(item['Item Name'], ':', item['Data'])
            except KeyError:
                print(item)
    
    def isBase64(sb):
        try:
            if isinstance(sb, str):
                    # If there's any unicode here, an exception will be thrown and the function will return false
                    sb_bytes = bytes(sb, 'ascii')
            elif isinstance(sb, bytes):
                    sb_bytes = sb
            else:
                    raise ValueError("Argument must be string or bytes")
            return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
        except Exception:
                return False

    def collect_logs(self):
        s3 = boto3.client('s3')
        log_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open('application.log','rb') as f:
            s3.upload_fileobj(f, self.s3, f'application_log_{log_date}.log')
            # os.remove('application.log')
            return True
        return False
    def upload_securely(self):
        self.refresh_data().to_csv(CONSTANTS.DATA_FILE_CSV,columns=['Type','Category','PII'])
        s3 = boto3.client('s3')
        df = pd.read_csv(CONSTANTS.DATA_FILE_CSV)
        for i in df.index:
            if df.loc[i, 'Type'] == 'KeyID':
                pass
            else:
                df.loc[i,'PII'] = base64.b64encode(self.cipher_suite.encrypt(df.loc[i,'PII'].encode('utf-8'))).decode('utf-8')
        # df.to_csv(file_path, index=False)
        try:
            with open(CONSTANTS.DATA_FILE_CSV, 'rb') as f:
                s3.upload_fileobj(f, self.s3, CONSTANTS.DATA_FILE_CSV)
                os.remove(CONSTANTS.DATA_FILE_CSV)
                # print(f"File {CONSTANTS.DATA_FILE_CSV} uploaded to S3 successfully.")
                return True
        except Exception as e:
            print(f"Error uploading file to S3: {e}")
            return False

    
    def process_file(self,mode,data=None,file_path=None):
        if file_path:
            path = file_path
        else:
            path = self.input_path
        if 'r' in mode:
            with open(path, mode) as f:
                data = f.read()
        elif 'w' in mode:
            with open(path,mode) as f:
                data = f.write(data)
                self.stored_file_names.append(path)
                print('Stored: ', path)
                return True  
        return data

    
    
    def end_work(self):
        for file in [self.encrypt_path,'encrypted_data_key.txt']:
            self.stored_file_names.remove(file) if file in self.stored_file_names else None
        while self.stored_file_names:
            file = self.stored_file_names.pop()
            os.remove(file)
            time.sleep(0.5)
        self.status['Post Exit CleanUp: All'] = self.get_current_time()


if __name__ == '__main__':
    
    agent = Agent(s3=CONSTANTS.AWS_S3,file_name=CONSTANTS.AWS_FILE)
    # agent.upload_excel_to_s3('MyPII.PIIData.xlsx')
    # agent.perform_specific_output()
    agent.download_excel()
    # agent.begin_work()