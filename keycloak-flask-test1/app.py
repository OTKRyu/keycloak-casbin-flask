import logging

from flask import Flask, make_response, request
from flask_oidc import OpenIDConnect
from casbin import Enforcer
from casbin.persist.adapters import FileAdapter
import jwt

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config.update({
    'SECRET_KEY': 'SomethingNotEntirelySecret',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'flask-test1',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    'PUBLIC_KEY': """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtGTTVSjgLw0jsWEmXY1JqRxb8NnuVaBXLX+PFkOdyUBBX46p8DS3QuVxyhzPsy5APpfXnCX04+MqGq5H+ieBqyJ+3v1F1L4iq5h5mD8lUv9MFoP47jah1CPjxLJnmEyb2E31DX5OGLVlUO71ycY/5Dpw23GeR5EgNBf0Q5e0fK9iNaGIHarO2dlLWXaKLQCeLAB5xYaYXuVE4guLNO8a5XccXkgirebQDRGfEcPmSvyEbyww/bZHRBJc5378FhJHtjt5IoWYN2rpBveE/LYBvV0/K+pwBtcZCDvmocfTjrhwEugGTojqvmo+0FqgmXl5dNoMie8Puofw/s81mzypwIDAQAB
-----END PUBLIC KEY-----""",
    'CASBIN_POLICY': 'C:/Users/user/Desktop/test/keycloak-flask-test1/rbac_policy.csv',
    'CASBIN_MODEL': 'C:/Users/user/Desktop/test/keycloak-flask-test1/casbinmodel.conf',
    'AUDIENCE': 'account',
})

oidc = OpenIDConnect(app)

adapter = FileAdapter(app.config['CASBIN_POLICY'])
e = Enforcer(app.config['CASBIN_MODEL'], adapter)

@app.route('/')
def home():
    if oidc.user_loggedin:
        preferred_username = oidc.user_getfield('preferred_username')
        html = f'''Hello, {preferred_username}, this is test1
        <br> 
        <a href="/login">See login</a>
        <br>
        <a href="/admin1">See admin1</a>
        <br>
        <a href="/admin2">See admin2</a>
        <br>
        <a href="/manager1">See manager1</a>
        <br>
        <a href="/manager2">See manager2</a>
        <br>
        <a href="/casbin_reload">reload casbin settings</a>
        <br>
        <a href="/logout">Log out</a>'''        
        response = make_response(html)
        return response
    else:
        return 'Welcome anonymous, this is test1 <a href="/login">Log in</a>'


@app.route('/login', methods=['GET'])
@oidc.require_login
def login_only():
    access_token = oidc.get_access_token()
    print(oidc.credentials_store)
    response = make_response('you are login user')
    if access_token:
        response.set_cookie('access_token', access_token) 
    return response

@app.route('/manager1', methods=['GET'])
@oidc.require_login
def manager1():
    access_token = request.cookies.get('access_token')
    if access_token:
        decoded_token = jwt.decode(access_token, app.config['PUBLIC_KEY'], algorithms=["RS256"], audience=app.config['AUDIENCE'])
    try:
        print(decoded_token)
        roles =  decoded_token["resource_access"][app.config['OIDC_OPENID_REALM']]["roles"]
        print(roles)
        path = request.path
        method = request.method
        for role in roles:
            print(f'{role} {path} {method}')
            if e.enforce(role, path, method):
                response = 'you are in manager1'
                print(response)
                return response
        response = make_response('you are not permitted') 
        return response
    except:
        response = make_response("you don't belong here") 
        return response

@app.route('/manager2', methods=['GET'])
@oidc.require_login
def manager2():
    access_token = request.cookies.get('access_token')
    if access_token:
        decoded_token = jwt.decode(access_token, app.config['PUBLIC_KEY'], algorithms=["RS256"], audience=app.config['AUDIENCE'])
    try:
        roles =  decoded_token["resource_access"][app.config['OIDC_OPENID_REALM']]["roles"]
        path = request.path
        method = request.method
        for role in roles:
            print(f'{role} {path} {method}')
            if e.enforce(role, path, method):
                response = make_response('you are in manager2')
                return response
        response = make_response('you are not permitted') 
        return response
    except:
        response = make_response("you don't belong here") 
        return response

@app.route('/admin1', methods=['GET'])
@oidc.require_login
def admin1():
    access_token = request.cookies.get('access_token')
    if access_token:
        decoded_token = jwt.decode(access_token, app.config['PUBLIC_KEY'], algorithms=["RS256"], audience=app.config['AUDIENCE'])
    try:
        roles =  decoded_token["resource_access"][app.config['OIDC_OPENID_REALM']]["roles"]
        path = request.path
        method = request.method
        for role in roles:
            print(f'{role} {path} {method}')
            if e.enforce(role, path, method):
                response = make_response('you are in admin1')
                return response
        response = make_response('you are not permitted') 
        return response
    except:
        response = make_response("you don't belong here") 
        return response

@app.route('/admin2', methods=['GET'])
@oidc.require_login
def admin2():
    access_token = request.cookies.get('access_token')
    if access_token:
        decoded_token = jwt.decode(access_token, app.config['PUBLIC_KEY'], algorithms=["RS256"], audience=app.config['AUDIENCE'])
    try:
        roles =  decoded_token["resource_access"][app.config['OIDC_OPENID_REALM']]["roles"]
        path = request.path
        method = request.method
        for role in roles:
            print(f'{role} {path} {method}')
            if e.enforce(role, path, method):
                response = make_response('you are in admin2')
                return response
        response = make_response('you are not permitted') 
        return response
    except:
        response = make_response("you don't belong here") 
        return response
    
@app.route('/logout')
def logout():
    """Performs local logout by removing the session cookie."""
    response = make_response('Hi, you have been logged out! <a href="/">Return</a>')
    response.set_cookie('access_token', '', expires=0)
    oidc.logout()
    return response

@app.route('/casbin_reload', methods=['GET'])
def casbin_reload():
    try:
        e.load_model()
        e.load_policy()
        return 'Success'
    except:
        return 'fail, pleaze ask to administrator'

if __name__ == '__main__':
    app.run()