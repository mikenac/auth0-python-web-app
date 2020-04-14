"""Python Flask WebApp Auth0 integration example
"""
from functools import wraps
import json
import uuid
from os import environ as env
from werkzeug.exceptions import HTTPException
from datetime import datetime, timedelta
from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect, request, url_for, Response, make_response
from flask import render_template
from flask import session, abort
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode
from urllib.parse import urlparse

import constants
from looker import Looker, User, URL

ENV_FILE = find_dotenv()
if ENV_FILE:
    print("loading environment file")
    load_dotenv(ENV_FILE)

AUTH0_CALLBACK_URL = env.get(constants.AUTH0_CALLBACK_URL)
AUTH0_CLIENT_ID = env.get(constants.AUTH0_CLIENT_ID)
AUTH0_CLIENT_SECRET = env.get(constants.AUTH0_CLIENT_SECRET)
AUTH0_DOMAIN = env.get(constants.AUTH0_DOMAIN)
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = env.get(constants.AUTH0_AUDIENCE)

app = Flask(__name__, static_url_path='/public', static_folder='./public')
app.secret_key = constants.SECRET_KEY
app.debug = True

@app.errorhandler(403)
def custom_403(error):
    return render_template('401.html'), 403

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

def create_noonce(request_args):
    url = request.args.get('next') or request.referrer or None
    id = str(uuid.uuid4())
    noonce = {
        id: {
            'redirectUrl': url,
            'expiresOn': datetime.utcnow() + timedelta(minutes=5)
        }
    }
    return (id, noonce)

def validate_noonce(noonce, key):
    expired = False
    expires = noonce[key]["expiresOn"]
    redirectUrl = noonce[key]["redirectUrl"]
    print(f"Expires: {expires}, RedirectUrl: {redirectUrl}")
    return (expires < datetime.utcnow(), redirectUrl)


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if constants.PROFILE_KEY not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated


# Controllers API
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/callback')
def callback_handling():
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    session[constants.JWT_PAYLOAD] = userinfo
    session[constants.PROFILE_KEY] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    print(f"callback args: {request.args}")
    noonce_id = request.args.get('state')
    if noonce_id in session:
        print(f"Found noonce for session: {noonce_id}")
        (expired, return_url) = validate_noonce(session[noonce_id], noonce_id)
        session.pop(noonce_id)
        print(f"ReturnURL: {return_url}")
        url_parts = urlparse(return_url)
        is_root = url_parts.path == "/"
        next_url = url_for('dashboard')
        if (expired or is_root):
            next_url = url_for('dashboard')
        else:
            next_url = return_url
    else:
        print("Not authorized by role")
        abort(403)
    return redirect(next_url)


@app.route('/login')
def login():
    (id, noonce) = create_noonce(request.args)
    #print(f"validated: {validate_noonce(noonce, id)}")
    session[id] = noonce
    return auth0.authorize_redirect(redirect_uri=AUTH0_CALLBACK_URL, audience=AUTH0_AUDIENCE, 
        state=id)


@app.route('/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for('home', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


def get_looker_biz(looker_url):
    looker = Looker(env.get(constants.LOOKER_APP), env.get(constants.LOOKER_SECRET))
    user_biz = session[constants.JWT_PAYLOAD]
    roles = user_biz["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"]
    if "TeleSupport" not in roles:
        abort(403)
    user = User(user_biz['sub'],
              first_name=user_biz['name'],
              last_name=user_biz['name'],
              permissions=['see_lookml_dashboards', 'see_user_dashboards', 'access_data'],
              models=['teletracking', 'covid'],
              group_ids=[],
              external_group_id='teletracking',
              user_attributes={"tenant_id": user_biz['https://example.com/tenant_id']},
              access_filters={})

    fifteen_minutes = 15 * 60

    url = URL(looker, user, fifteen_minutes, looker_url,
        embed_domain='https://looker-sso.herokuapp.com', 
        force_logout_login=True)
    return f"https://{url.to_string()}"


@app.route('/dashboard/<dashboard_id>')
@requires_auth
def dashboards(dashboard_id):
    url = get_looker_biz(f"/embed/dashboards/{dashboard_id}")
    return render_template('embedded.html', url=url)


@app.route('/analytics')
@requires_auth
def analytics():
    
    url = get_looker_biz('/embed/dashboards/7')
    print(f"url={url}")
    return render_template('embedded.html', url=url)


@app.route('/dashboard')
@requires_auth
def dashboard():
    print(session)
    return render_template('dashboard.html',
                           userinfo=session[constants.PROFILE_KEY],
                           userinfo_pretty=json.dumps(session[constants.JWT_PAYLOAD], indent=4))


if __name__ == "__main__":
    app.run()
