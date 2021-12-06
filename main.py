"""Python Flask WebApp Auth0 integration example
"""
from functools import wraps
import json

from flask.json import loads
from jose import jwt
from os import environ as env
from werkzeug.exceptions import HTTPException
import requests
from dotenv import load_dotenv, find_dotenv
from flask import Flask, jsonify, redirect, render_template, url_for, request, session
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode
from six.moves.urllib.request import urlopen
from google.cloud import datastore
import constants

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

AUTH0_CALLBACK_URL = env.get(constants.AUTH0_CALLBACK_URL)
AUTH0_CLIENT_ID = env.get(constants.AUTH0_CLIENT_ID)
AUTH0_CLIENT_SECRET = env.get(constants.AUTH0_CLIENT_SECRET)
AUTH0_DOMAIN = env.get(constants.AUTH0_DOMAIN)
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = env.get(constants.AUTH0_AUDIENCE)
ALGORITHMS = ["RS256"]

app = Flask(__name__, static_url_path='/public', static_folder='./public')
app.secret_key = constants.SECRET_KEY
app.debug = True
client = datastore.Client()



@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response


oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oauth/token',
    authorize_url=AUTH0_BASE_URL + '/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ AUTH0_DOMAIN +"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=AUTH0_CLIENT_ID,
                issuer="https://"+ AUTH0_DOMAIN +"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if constants.PROFILE_KEY not in session:
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated


#
# 
# 
# Login
# 
# 
@app.route('/')
def home():
    return render_template('home.html')

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          


# Here we're using the /callback route. - Adapted from auth0 tutorial: https://auth0.com/docs/quickstart/webapp/python#configure-callback-urls
@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    session['jwt_token'] = auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    # Store the user in the database
    query = client.query(kind=constants.users)
    query.add_filter("user_id", "=", userinfo['sub'])
    results = list(query.fetch())
    
    print(userinfo['sub'])
    print(results)
    if(not results):
        new_user = datastore.entity.Entity(key=client.key(constants.users))
        new_user.update({"email": userinfo['name'], "user_id": userinfo['sub']})
        client.put(new_user)

    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
     
    return redirect('/dashboard')


# route to display user information, only accessible if authorized
@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session['profile'],
                           jwt_token=session['jwt_token']['id_token'],
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4))

@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=AUTH0_CALLBACK_URL, audience=AUTH0_AUDIENCE)

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login2', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':AUTH0_CLIENT_ID,
            'client_secret':AUTH0_CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + AUTH0_DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type':'application/json'}


# Route to logout
@app.route('/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for('home', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

#
#
#
# Users
#
#
#

# Route to display all users 
@app.route('/users')
def get_user():
    query = client.query(kind=constants.users)
    results = list(query.fetch())
    return jsonify(results), 200

#
#
# Boats
#
#

# Create a boat if the Authorization header contains a valid JWT
@app.route('/boats', methods=['POST', 'GET'])
def boats_post_get():
    # POST Boat - create a new boat 
    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        if(len(content) != 3):
            return  jsonify({"Error": "The request object is missing at least one of the required attributes"}) , 400
        new_boat = datastore.entity.Entity(key=client.key(constants.boats))
        new_boat.update({"name": content["name"], "type": content["type"],
                        "length": content["length"], "owner" : payload["sub"], "loads": []})
        client.put(new_boat)
        new_boat.update({"id": new_boat.key.id, "self": str(
                request.base_url) + "/" + str(new_boat.key.id)})
        return jsonify(new_boat), 201
    
    # GET Boats for the JWT/user
    elif request.method == 'GET':
        # Check for JWT
        payload = verify_jwt(request)
        # retrive all boats from the owner
        query = client.query(kind=constants.boats)
        query.add_filter("owner", "=", payload["sub"])
        boat_count = len(list(query.fetch()))
        # paginate respose
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        # add id and self 
        for e in results:
            e["id"] = e.key.id
            e["self"] = str(request.base_url) + "/" + str(e.key.id)
        # format response
        output = {"boats": results}
        if next_url:
            output["next"] = next_url
        output["count"] = boat_count
        return jsonify(output)
    else:
        return jsonify(error='Method not recogonized'), 405


@app.route('/boats/<id>', methods={'GET', 'PATCH', 'DELETE'})
def boat_get_patch_delete(id):
    # Check for JWT
    verify_jwt(request)
    if request.method == 'GET':
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if(boat is None):
            return jsonify({"Error": "No boat with this boat_id exists"}), 404
        boat['id'] = id
        boat["self"] = str(request.base_url)
        return jsonify(boat), 200
    
    elif request.method == "DELETE":
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if(boat is None):
            return jsonify({"Error": "No boat with this boat_id exists"}), 404
        # clear the load.carrier if a boat is deleted
        query = client.query(kind=constants.loads)
        results = list(query.fetch())
        for load in results:
            if load["carrier"] is not None:
                if load["carrier"]["id"] == int(id):
                    load["carrier"] = None
                    client.put(load)
        client.delete(boat_key)
        return (jsonify(''), 204)
    
    else:
        return 'Method not recognized'
#
#
# Loads
#
#


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=env.get('PORT', 3000))