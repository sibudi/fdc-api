SQL_CONNECTION = {}
INTERNAL_BUCKET = {}
PUBLIC_BUCKET = {}
NOTIFICATION_CONFIG = {}
ORIGIN = ""

def connect_to_mysql(context, mysql_config):
 import minipymysql as pymysql
 return pymysql.connect(
  host=mysql_config['host'],
  port=3306,
  user=mysql_config['username'],
  password=decrypt_string(context, mysql_config['password']),
  db=mysql_config['db'],
  charset='utf8mb4',
  cursorclass=pymysql.cursors.DictCursor)

def get_configuration(context, group_code):
 import os
 from tablestore import OTSClient
 creds = context.credentials
 client = OTSClient(os.environ['TABLE_STORE_ENDPOINT'],
  creds.accessKeyId, creds.accessKeySecret,
  os.environ['TABLE_STORE_INSTANCE_NAME'],
  sts_token=creds.securityToken)
 primary_key = [('group', group_code)]
 columns_to_get = []
 consumed, return_row, next_token = client.get_row(
  os.environ['TABLE_STORE_TABLE_NAME'],
  primary_key,
  columns_to_get, None, 1)
 json = {}
 for att in return_row.attribute_columns:
  json[att[0]] = att[1]
 return json

def decrypt_string(context, encrypted_string):
 import json
 from aliyunsdkcore.auth import credentials
 from aliyunsdkcore.client import AcsClient  
 from aliyunsdkkms.request.v20160120.DecryptRequest import DecryptRequest
 creds = context.credentials
 sts_credentials = credentials.StsTokenCredential(creds.accessKeyId, creds.accessKeySecret, creds.securityToken) 
 client = AcsClient(region_id = 'ap-southeast-5',credential = sts_credentials)
 request = DecryptRequest()
 request.set_CiphertextBlob(encrypted_string)
 response = str(client.do_action_with_exception(request), encoding='utf-8')
 return json.loads(response)['Plaintext']

def is_json(myjson):
  import json
  try:
    json_object = json.loads(myjson)
  except ValueError as e:
    return False
  return True

def signOssObject(http_method, file_name, expiration_time, headers=None, public_access=True):
  import json
  bucket = PUBLIC_BUCKET

  signed_url = f"{bucket.sign_url(http_method, file_name, expiration_time, headers)}"
  return signed_url

#######################################################################
########################### HELPER FUNCTION ###########################
#######################################################################
def send_email(subject, message, to, cc=None, bcc=None, attachments=None):
  import requests
  import json
  data = {
    "subject": subject,
    "message": message,
    "to": to,
    "cc": cc if cc is not None else "",
    "bcc": bcc if bcc is not None else "",
    "attachments": attachments if attachments is not None else []
  }
  
  token = NOTIFICATION_CONFIG['x-authorization-token']
  endpoint = NOTIFICATION_CONFIG['endpoint']
  headers = {'Content-Type': 'application/json', 'x-authorization-token': token, 'Origin':f"{NOTIFICATION_CONFIG['endpoint'].replace('notificationapi', ORIGIN)}"}
  resp = requests.post(f"{endpoint}/email",
      data=json.dumps(data), headers=headers)
