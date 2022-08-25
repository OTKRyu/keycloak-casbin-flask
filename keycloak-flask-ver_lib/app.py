import logging

from flask import Flask, make_response, request
from flask_oidc import OpenIDConnect
from casbin import Enforcer
from casbin.persist.adapters import FileAdapter

from common_authorization import Authorization

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
    'PUBLIC_KEY': """{your keyclock public key}""",
    'CASBIN_POLICY': '{your policy location}',
    'CASBIN_MODEL': '{your policy location}',
    'AUDIENCE': 'account',
    'LOGIN_URL': '/login',
})

oidc = OpenIDConnect(app)


adapter = FileAdapter(app.config['CASBIN_POLICY'])
enforcer = Enforcer(app.config['CASBIN_MODEL'], adapter)

authorization = Authorization(app, enforcer)

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
    response = make_response('you are login user')
    if access_token:
        response.set_cookie('access_token', access_token) 
    return response

@app.route('/manager1', methods=['GET'])
@authorization.custom_login_required
@authorization.custom_authorization_required
def manager1():
    response = 'you are in manager1'
    return response

@app.route('/manager2', methods=['GET'])
@authorization.custom_login_required
@authorization.custom_authorization_required
def manager2():
    response = make_response('you are in manager2')
    return response

@app.route('/admin1', methods=['GET'])
@authorization.custom_login_required
@authorization.custom_authorization_required
def admin1():
    response = make_response('you are not permitted') 
    return response
@app.route('/admin2', methods=['GET'])
@authorization.custom_login_required
@authorization.custom_authorization_required
def admin2():
    response = make_response('you are in admin2')
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
        enforcer.load_model()
        enforcer.load_policy()
        return 'Success'
    except:
        return 'fail, pleaze ask to administrator'

if __name__ == '__main__':
    app.run()