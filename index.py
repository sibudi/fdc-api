import helper
import json
import logging
import minirouter
import requests
from requests.auth import HTTPBasicAuth


logger = {}
fdc_config_v1 = {}
fdc_config_v35 = {}
@minirouter.route(methods=['GET'], content_type='text/plain', path=['/v1/inquiry'])
def inquiry():
    query_string = minirouter.router.getQueryString()
    context = minirouter.router.getContext()
    fdc_config = fdc_config_v1 if query_string.get('v', 0) == '1' else fdc_config_v35

    url = fdc_config['url']
    password = helper.decrypt_string(context, fdc_config['password'])
    params = {
        'id' : query_string['id'],
        'reason' : query_string['reason'],
        'reffid' : query_string['reffid'] 
    }
    headers = {'Content-Type': 'application/json'}
    auth = HTTPBasicAuth(fdc_config['username'], password)
    resp = requests.get(url, params, headers=headers, auth=auth)
    return minirouter.return_200(resp.text)


######################################################################
########################## HANDLER FUNCTION ##########################
######################################################################
def init(context):
  try:
    global logger
    global fdc_config_v1
    global fdc_config_v35
    logger = logging.getLogger()
    minirouter.router.initialize(ROUTER_FILE_NAME=__name__, ROUTER_AUDIENCE='')#jwt_config["audience"])
    
    # url_auth_v1 bisa hit dari mana saja, url_auth_v35: hit dari backend server
    fdc_config_v1 = helper.get_configuration(context, 'url_auth_v1')
    fdc_config_v35 = helper.get_configuration(context, 'url_auth_v35')
    
    #helper.NOTIFICATION_CONFIG = helper.get_configuration(context, 'notification')
    #helper.ORIGIN=context.service.name
  
  except Exception as ex:
    logger.error(ex)
    raise Exception("Internal Server Error - Failed when initializing")
  
  return ""

def handler(event, context):
  try:
    return minirouter.router.routeRequest(event, context)
  except minirouter.base_router.RouteException as rex:
    logger.error(rex)
    if (rex.code == "400"):
      return minirouter.return_400(rex.message)
    else:
      return minirouter.return_500(rex.message)
  except Exception as error:
    import traceback
    logger.error(error)
    logger.error(traceback.format_exc())
    return minirouter.return_500(error)