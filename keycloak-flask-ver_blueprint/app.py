import logging

from flask import Flask, make_response, request

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
    'UPLOAD_FOLDER': '{your upload folder location}',
})

from custom_enforcer import Custom_Enforcer
from custom_oidc import Custom_Oidc

oidc = Custom_Oidc.get_oidc(app)

enforecer = Custom_Enforcer.get_enforcer(app.config['CASBIN_MODEL'], app.config['CASBIN_POLICY'])
from common_authorization import custom_authorization_required, custom_login_required, get_decoded_token

from casbin_blueprint import casbin
from auth_blueprint import auth

app.register_blueprint(casbin)
app.register_blueprint(auth)


@app.route('/')
def home():
    if request.cookies.get('access_token'):
        decoded_token = get_decoded_token(request.cookies.get('access_token'))
        preferred_username = decoded_token.get('preferred_username')
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
        <a href="//localhost:{keycloak port}/realms/myrealm/account?referrer=flask-test1&referrer_uri=http://localhost:{your app port}/&">Account
        <br>
        <a href="/logout">Log out</a>'''        
        response = make_response(html)
        return response
    else:
        return 'Welcome anonymous, this is test1 <a href="/login">Log in</a>'

@app.route('/manager1', methods=['GET'])
@custom_login_required
@custom_authorization_required
def manager1():
    response = 'you are in manager1'
    return response

@app.route('/manager2', methods=['GET'])
@custom_login_required
@custom_authorization_required
def manager2():
    response = make_response('you are in manager2')
    return response

@app.route('/admin1', methods=['GET'])
@custom_login_required
@custom_authorization_required
def admin1():
    response = make_response('you are in admin1') 
    return response

@app.route('/admin2', methods=['GET'])
@custom_login_required
@custom_authorization_required
def admin2():
    response = make_response('you are in admin2')
    return response

if __name__ == '__main__':
    app.run()