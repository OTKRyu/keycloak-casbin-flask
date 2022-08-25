from functools import wraps

from flask import request, redirect
import jwt


class Authorization:
    def __init__(self, app, enforcer):
        self.app = app
        self.enforcer = enforcer

    def custom_login_required(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if request.cookies.get('access_token'):
                return func(*args, **kwargs)

            return redirect(self.app.config['LOGIN_URL'])

        return wrapper

    def custom_authorization_required(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not request.cookies.get('access_token'):
                return redirect(self.app.config['LOGIN_URL'])

            access_token = request.cookies.get('access_token')

            try:
                decoded_token = jwt.decode(access_token, self.app.config['PUBLIC_KEY'], algorithms=["RS256"], audience=self.app.config['AUDIENCE'])
                roles = decoded_token["resource_access"][self.app.config['OIDC_OPENID_REALM']]["roles"]
                
                path = request.path
                method = request.method
                for role in roles:
                    if self.enforcer.enforce(role, path, method):
                        return func(*args, **kwargs)
                               
                return 'you are not permitted'
            except:
                return "you don't belong here"

        return wrapper    


