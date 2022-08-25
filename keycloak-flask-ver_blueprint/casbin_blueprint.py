from urllib.error import HTTPError
from flask import Blueprint, request, make_response
from custom_enforcer import Custom_Enforcer

casbin = Blueprint('casbin', __name__)
enforcer = Custom_Enforcer.get_enforcer()

@casbin.route('/casbin_reload', methods=['GET'])
def casbin_reload():
    try:
        enforcer.load_model()
        enforcer.load_policy()
        return 'Success'
    except:
        return 'fail, pleaze ask to administrator'

@casbin.route('/change_casbin', methods=['GET','POST'])
def change_casbin():
    if request.method == "GET":
        response = make_response('''
        <html>
            <body>
                <form action = "http://localhost:5000/change_casbin" method = "POST" 
                    enctype = "multipart/form-data">
                    <input type = "file" name = "file" />
                    <input type = "submit"/>
                </form>   
            </body>
        </html>
        ''')
        return response

    if request.method == "POST":
        f = request.files['file']
        f.save(f.filename)
        return 'file uploaded successfully'

    response = make_response('500 Internal Server Error')
    return response


