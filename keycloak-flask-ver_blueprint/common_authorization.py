from functools import wraps

from flask import request, redirect, current_app
import jwt

from custom_enforcer import Custom_Enforcer

enforcer = Custom_Enforcer.get_enforcer()

def get_decoded_token(access_token):
    if access_token:
        try:
            decoded_token = jwt.decode(access_token, current_app.config['PUBLIC_KEY'], algorithms=["RS256"], audience=current_app.config['AUDIENCE'])
            return decoded_token
        except:
            raise 'decoding token failed, maybe not vaild token for auth server'

    raise 'access_token required'

def custom_login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if request.cookies.get('access_token'):
            return func(*args, **kwargs)

        return redirect(current_app.config['LOGIN_URL'])

    return wrapper

def custom_authorization_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        access_token = request.cookies.get('access_token')
        decoded_token = get_decoded_token(access_token)
        try:
            roles = decoded_token["resource_access"][current_app.config['OIDC_OPENID_REALM']]["roles"]
            path = request.path
            method = request.method

            for role in roles:
                if enforcer.enforce(role, path, method):
                    return func(*args, **kwargs)
                            
            return 'you are not permitted'
        except:
            return "you don't belong here"

    return wrapper    


