from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate
from functools import lru_cache, wraps
import base64
import hashlib
import hmac
import http.client
import inspect
import json
import os
import sys
import urllib.parse

DEBUG = True
import logging
logger = logging.getLogger()
######################################################################
############################# DECORATOR ##############################
######################################################################
def authorization(**dkwargs):
    dkwargs["__fingerprint__"] = "authorization"
    dkwargs["__version__"] = "0.1.0"
    def inner_function(function):  
        @wraps(function)
        def wrapper(*args, **kwargs):
            if "jwt_validation" in dkwargs and dkwargs['jwt_validation'] == True:
                auth_validation=validateAuth(router.getRequestHeaders(), dkwargs)
                if auth_validation["code"] != "200":
                    raise base_router.RouteException(auth_validation)
            elif "auth_method" in dkwargs and inspect.isfunction(function):
                custom_validation=dkwargs["auth_method"](router.getRequestHeaders(), dkwargs)
                if custom_validation["code"] != "200":
                    raise base_router.RouteException(custom_validation)
            return function(*args, **kwargs)
        return wrapper
    return inner_function

def route(**dkwargs):
    dkwargs["__fingerprint__"] = base_router.WRAPPER_NAME
    dkwargs["__version__"] = "0.1.3-apg"
    def inner_function(function):  
        @wraps(function)
        def wrapper(*args, **kwargs):
            return function(*args, **kwargs)
            #???Somehow if we don't call dkwargs in this method, it will throw an error???
            #Eventhough this code is unreachable
            lambda x: dkwargs
        return wrapper
    return inner_function

class base_router():
    WRAPPER_NAME = "ROUTE"
    def initialize(self, **dkwargs):
        self.ROUTER_FILE_NAME = dkwargs["ROUTER_FILE_NAME"]
        self.ROUTER_AUDIENCE = dkwargs["ROUTER_AUDIENCE"]
    def routeRequest(self, event, context):
        event = json.loads(event)
        self.EVENT = event
        self.CONTEXT = context
        event['headers'] = {k.lower():v for k,v in event['headers'].items()}
        token = event['headers']['x-auth-token'] if 'x-auth-token' in event['headers'] else None
        self.TOKEN = json.loads(base64.b64decode(token.split(".")[1]+"====").decode('utf-8')) if token is not None else {}
        self.REQUEST_METHOD = event["httpMethod"].upper()
        #Currently Api gateway always replacing the content-type into text/plain 
        self.CONTENT_TYPE = event["headers"]["content-type"].lower() if "content-type" in event["headers"] else "text/plain"
        self.PATH_INFO = event["path"].lower()
        self.QUERY_STRING = event["queryParameters"] if "queryParameters" in event else {}
        self.REQUEST_HEADERS = event["headers"]
        self.REQUEST_BODY = base64.b64decode(event['body']) if event['isBase64Encoded'] == True else event['body']
        
        if (DEBUG):
            logger.info("RequestHeaders: {0}".format(self.REQUEST_HEADERS))
            logger.info("RequestMethod:{0} || Path:{1} || QueryString:{2} || RequestBody: {3}".format(self.REQUEST_METHOD, self.PATH_INFO, self.QUERY_STRING, self.REQUEST_BODY))
            
        # Validate token audience
        #print("VALIDATE TOKEN")
        if self.TOKEN and not (self.TOKEN['aud'] == self.ROUTER_AUDIENCE or self.ROUTER_AUDIENCE in self.TOKEN['aud']):
            raise self.RouteException({ 'code':'400', 'message': 'Invalid token audience'})
        #print("VALIDATE CONTENT TYPE")
        if "application/json" in self.CONTENT_TYPE:
            try:
                self.REQUEST_BODY = json.loads(self.REQUEST_BODY.decode('UTF-8'))
            except ValueError as e:
                raise self.RouteException({ 'code':'400', 'message': 'Invalid Request body. Expecting json'})
        self.FUNCTIONS = {}
        for name,obj in inspect.getmembers(sys.modules[self.ROUTER_FILE_NAME]):  
            if inspect.isfunction(obj) and hasattr(obj,"__closure__") and obj.__closure__ is not None:
                decorator = self.findRouteDecorator(obj.__closure__)
                if decorator is not None:
                    for path in decorator['path']:
                        self.FUNCTIONS[path] = {
                            "func_name": name, 
                            "obj": obj, 
                            "methods": decorator['methods'],
                            "content_type": decorator['content_type']
                        }
        #print("VALIDATE ROUTE")
        func = self.validateRoute()
        #print("RUNNING FUNCTION")
        return func()
    def findRouteDecorator(self, closure):
        decorator = closure[0].cell_contents
        if (not inspect.isfunction(decorator)
            and  "__fingerprint__" in decorator
            and decorator["__fingerprint__"] == self.WRAPPER_NAME
            and "path" in decorator 
            and "methods" in decorator 
            and "content_type" in decorator):
            return decorator
        elif inspect.isfunction(closure[1].cell_contents):
            return self.findRouteDecorator(closure[1].cell_contents.__closure__)
        else:
            return None
    def validateRoute(self):
        func = {}
        request_fragments = self.PATH_INFO.split("/")[1:]
        for route in self.FUNCTIONS.keys():
            function_fragments = route.lower().split("/")[1:]
            if len(function_fragments) != len(request_fragments) :
                #Fragment is difference, continue searching other function
                continue     
            for i in range(len(function_fragments)):
                fragment = function_fragments[i].lower()
                if fragment[0] == "{" and fragment[-1] == "}":
                    #Get path variable for REST api
                    self.QUERY_STRING[fragment[1:-1]] = request_fragments[i]
                elif fragment != request_fragments[i].lower():
                    #Route not match, continue searching for next function 
                    break
                if i == len(function_fragments)-1: 
                    #This is the last function fragment
                    func = self.FUNCTIONS[route]
            if func != {}:
                break   
        if func == {}:
            raise self.RouteException({ 'code':'400', 'message': f"Unknown Method: {self.PATH_INFO}"})
        elif "methods" in func and self.REQUEST_METHOD not in [x.upper() for x in func["methods"]]:
            raise self.RouteException({ 'code':'400', 'message': 'Method Unsupported'})
        elif "content_type" in func and func["content_type"].lower() not in self.CONTENT_TYPE:
            raise self.RouteException({ 'code':'400', 'message': 'Invalid Content Type'})
        else:
            return func["obj"]
    def getEvent(self):
        return self.EVENT
    def getContext(self):
        return self.CONTEXT
    def getRequestHeaders(self):
        return self.REQUEST_HEADERS
    def getRequestBody(self):
        return self.REQUEST_BODY
    def getQueryString(self):
        return self.QUERY_STRING
    def getPathInfo(self):
        return self.PATH_INFO
    class RouteException(Exception):
        def __init__(self, json):
            self.code = json['code']
            self.message = json['message']
        def __str__(self):
            return f"{self.code} - {self.message}"

def validateAuth(headers, dkwargs=[]):
    required_scopes = dkwargs['scope']
    isScopeValid = False
    #Doesn't need to validate token, because it will be validated by API Gateway
    token = headers["x-auth-token"]
    try:
        #Need to add ==== for fixing auth0 missing padding
        payload = json.loads(base64.b64decode(token.split(".")[1]+"====").decode('utf-8'))
        ##################
        # Validate scope #
        ##################
        if len(required_scopes) > 0:
            if "scope" in payload:
                token_scopes = payload["scope"].split()
                for token_scope in token_scopes:
                    if token_scope in required_scopes:
                        isScopeValid = True
                        break
            if "permissions" in payload:
                for permission in payload["permissions"]:
                    if permission in required_scopes:
                        isScopeValid = True
                        break
        else:
            isScopeValid = True
        if isScopeValid == False:
            return { 'code':'400', 'message':'Invalid scope' if DEBUG else 'Unauthorized'}
        else:
            return { 'code':'200', 'message':'Authorized'}
    except Exception as error:
        if (DEBUG):
            import traceback
            logger.error(error)
            logger.error(traceback.format_exc())
        return { 'code':'500', 'message':'Unhandled Internal Server Error' if DEBUG else 'Internal Server Error'}

def return_200(message):
 logger.info(f"ResponseBody: {message}")
 return {
  "isBase64Encoded": False,
  "statusCode": 200,
  "headers": {"content-type":"application/json"},
  "body": message
 }

def return_400(message):
 logger.warning(f"ResponseBody: {message} || PathInfo: {router.getPathInfo()} || RequestBody:{router.getRequestBody()}")
 return {
  "isBase64Encoded": False,
  "statusCode": 400,
  "headers": {"content-type":"application/json"},
  "body": f"{message}"
 }

def return_500(message):
 logger.error(f"ResponseBody: {message} || PathInfo: {router.getPathInfo()} || RequestBody:{router.getRequestBody()}")
 return {
  "isBase64Encoded": False,
  "statusCode": 500,
  "headers": {"content-type":"application/json"},
  "body": f"{message}"
 }

router = base_router()
