from flask import Blueprint, make_response
from custom_oidc import Custom_Oidc

oidc = Custom_Oidc.get_oidc()

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=["GET"])
@oidc.require_login
def login():
    access_token = oidc.get_access_token()
    print(oidc.credentials_store)
    response = make_response('you are login user')
    if access_token:
        response.set_cookie('access_token', access_token) 
    return response

@auth.route('/logout')
def logout():
    """Performs local logout by removing the session cookie."""
    response = make_response('Hi, you have been logged out! <a href="/">Return</a>')
    response.set_cookie('access_token', '', expires=0)
    oidc.logout()
    return response