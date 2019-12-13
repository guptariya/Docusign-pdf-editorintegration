"""Flask App Project."""

from flask import Flask, jsonify
from flask import render_template, url_for, redirect, session, flash, request,Response
import os
from flask import send_file, send_from_directory, safe_join, abort
import hashlib
import base64
from PIL import Image
import io
from werkzeug.utils import secure_filename
import requests 
import json
import uuid
from flask_uploads import UploadSet, IMAGES, configure_uploads
from werkzeug.datastructures import FileStorage
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask import Flask, session
from reportlab.pdfgen import canvas
import fitz
from io import StringIO
import urllib.request
from flask_session.__init__ import Session
import ds_config
#import pydocusign
#from pydocusign import client,models,api,test
from flask_oauthlib.client import OAuth
from datetime import datetime, timedelta
import requests
import uuid
import eg002_signing_via_email, eg011_embedded_sending,ds_config
#from flask_wtf.csrf import CsrfProtect
from flask_wtf.csrf import CSRFProtect


csrf = CSRFProtect()
app = Flask(__name__, instance_relative_config=True)
csrf.init_app(app)
app.secret_key = os.urandom(24)

#app.config['UPLOADED_DEFAULT_DEST'] = '/var/uploads'
#return_url = "http://127.0.0.1:5000"
#upload set configurations
pdf = UploadSet(extensions=('pdf','txt', 'rtf', 'odf', 'ods', 'gnumeric', 'abw', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpe', 'jpeg', 'png', 'gif', 'svg', 'bmp', 'csv', 'ini', 'json', 'plist', 'xml', 'yaml', 'yml'), default_dest=lambda app: app.instance_path)
configure_uploads(app, pdf)

pdf2 = UploadSet(extensions=('pdf','txt', 'rtf', 'odf', 'ods', 'gnumeric', 'abw', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpe', 'jpeg', 'png', 'gif', 'svg', 'bmp', 'csv', 'ini', 'json', 'plist', 'xml', 'yaml', 'yml'), default_dest=lambda app: app.instance_path)
configure_uploads(app, pdf2)


APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# client = client.DocuSignClient(
#     root_url='https://demo.docusign.net/restapi/v2.1',
#     username= 'riyagupta@tristonsoft.com',
#     password= 'creative123',
#     integrator_key='c0c6ac35-fa68-4a3d-9260-16b28d8f7a5e',
# )
@app.route('/')
def home():
    return render_template('home.html', name="home")


@app.route('/generateqr')
def generateqr():
    user= "shah.yogi+3@tristonsoft.com"
    key1 = "5f24f8087b6228edf456bb0da030c67c127a2fec"
    secret_key1= "KoGLt29m51dI8jeVz7rvzljUdGNMf9IdeEZP13M8KhChgjkCd4Z9EghLa9We"
    secret=key1+secret_key1
    hash_object = hashlib.sha256(str(secret).encode('utf-8'))
    payload = hash_object.hexdigest()
    url='http://veridocglobaldeveloper-stage.azurewebsites.net/api/generateqr'
    headers={'apikey':key1,'payload':payload,'content_type':'application/json'}
    header = {'content_type': 'application/json'}
    r=requests.post(url,headers=headers)
    data=r.json()
    a=json.dumps(data['uniqueId']).strip('"')
    qrlink = json.dumps(data['QR']).strip('"')
    session['link'] = qrlink
    b=json.dumps(data['qrImage'])
    base64src1=json.dumps(data['qrImage'])
    arr = []
    arr = b.split(',')
    b1 = arr[1]
    base64src1= base64src1.replace(".png","png")
    base64src1=base64src1.strip('"')
    session['base64str'] = base64src1
    image = base64.b64decode(str(b1))
    return base64src1


@app.route('/uploader', methods = ['GET', 'POST'])
def upload_file1():
    if request.method == 'POST':
        filename = pdf.save(request.files['file'])
        session['path'] = pdf.path(filename)
        url1 = pdf.url(filename)
        base64 = generateqr()
        session['base64'] = base64
        session['pdfurl']=url1
        return render_template("index.html",file_path=url1,base64 = base64)

@app.route('/savefile', methods = ['GET', 'POST'])
def savefile():
    if request.method == 'POST':
        hd_topValue = request.form.get('hd_topValue')
        hd_leftValue =request.form.get('hd_leftValue')
        hd_pageNumber =request.form.get('hd_pageNumber')
        hd_baseval = request.form.get('hd_baseval')
        b=hd_baseval
        arr = []
        arr = b.split(',')
        b1 = arr[1]
        b1= b1.replace(".png","png")
        b1=b1.strip('"')
        image = base64.b64decode(str(b1))
        im = Image.open(io.BytesIO(image))
        src_pdf_filename = session.get('path')#"static/download.pdf"#
        dst_pdf_filename = 'destination.pdf'
        remoteFile = urllib.request.urlopen(session.get('pdfurl')).read()
        
        document = fitz.open(stream=remoteFile,filetype='pdf')
        hd_pageNumber = int(hd_pageNumber)
        hd_pageNumber-= 1
        page = document[hd_pageNumber]
        
        x1 = sum([float(hd_leftValue),100])
        y1 = sum([float(hd_topValue),100])
        img_rect = fitz.Rect(hd_leftValue,hd_topValue,x1,y1)
        page.insertImage(img_rect, stream=image,overlay = True)
        document.save(dst_pdf_filename)
        document.close()
        #pdf.save(document)
        data = open('destination.pdf', "rb").read()

        new_pdf_basee64 = base64.b64encode(data)
        session["pdf_base_64"] = new_pdf_basee64
        return send_file(dst_pdf_filename,as_attachment=True)
   
@app.route("/in")
def index():
    return render_template("home1.html", title="Home - Python Code Examples")


@app.route("/ds/must_authenticate")
def ds_must_authenticate():
    return render_template("must_authenticate.html", title="Must authenticate")


@app.route("/eg002", methods=["GET", "POST"])
def eg002():
    return eg002_signing_via_email.controller()


@app.route("/eg011", methods=["GET", "POST"])
def eg011():
    return eg011_embedded_sending.controller()


def ds_token_ok(buffer_min=60):
    """
    :param buffer_min: buffer time needed in minutes
    :return: true iff the user has an access token that will be good for another buffer min
    """
    #token="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjY4MTg1ZmYxLTRlNTEtNGNlOS1hZjFjLTY4OTgxMjIwMzMxNyJ9.eyJUb2tlblR5cGUiOjUsIklzc3VlSW5zdGFudCI6MTU3NDgzNDE1OSwiZXhwIjoxNTc0ODYyOTU5LCJVc2VySWQiOiI1MzUyYzYwMi05MDdjLTQ4NzktYTQ1Mi05NjQ3MGJjOWZkMjciLCJzaXRlaWQiOjEsInNjcCI6WyJzaWduYXR1cmUiLCJjbGljay5tYW5hZ2UiLCJvcmdhbml6YXRpb25fcmVhZCIsImdyb3VwX3JlYWQiLCJwZXJtaXNzaW9uX3JlYWQiLCJ1c2VyX3JlYWQiLCJ1c2VyX3dyaXRlIiwiYWNjb3VudF9yZWFkIiwiZG9tYWluX3JlYWQiLCJpZGVudGl0eV9wcm92aWRlcl9yZWFkIiwiZHRyLnJvb21zLnJlYWQiLCJkdHIucm9vbXMud3JpdGUiLCJkdHIuZG9jdW1lbnRzLnJlYWQiLCJkdHIuZG9jdW1lbnRzLndyaXRlIiwiZHRyLnByb2ZpbGUucmVhZCIsImR0ci5wcm9maWxlLndyaXRlIiwiZHRyLmNvbXBhbnkucmVhZCIsImR0ci5jb21wYW55LndyaXRlIl0sImF1ZCI6ImYwZjI3ZjBlLTg1N2QtNGE3MS1hNGRhLTMyY2VjYWUzYTk3OCIsImF6cCI6ImYwZjI3ZjBlLTg1N2QtNGE3MS1hNGRhLTMyY2VjYWUzYTk3OCIsImlzcyI6Imh0dHBzOi8vYWNjb3VudC1kLmRvY3VzaWduLmNvbS8iLCJzdWIiOiI1MzUyYzYwMi05MDdjLTQ4NzktYTQ1Mi05NjQ3MGJjOWZkMjciLCJhdXRoX3RpbWUiOjE1NzQ4MzM2MTYsInB3aWQiOiIwY2VmOTVlZC03MGU1LTRjZTgtOWM3Ny0wNzU3MTNmMWQwOTUifQ.szC5or79bQbFmq8i0OO8j4KIYZd0zIc9CYsMdpxM2mlX7xqQzVNO5xInauqTINUtsllXWDiHprPOpX0I8FWiF0X7sG8suS5v2dKuLpvjobLhbIyxPSL8tl2Vv13i3Co3VcJVARaQ2bCMET10hDcaqy_L0OqcON1e8hUUk_lgESqvglhucs7Z_CBUrt_fSJv1tz7DHtTeIHISvqLvzF4phC-ZDj_lw6zHrr-RFQE-fhg-ccPYYdqLEEVpCACxVBnzVYodvKZ_LX1FBckd72Bh6hydplTIPN4-n_x3ZE4jLt2lKqBbOB-LUaAKFLjlt6t-YuiE-VRb43n0v0oSgmWgDw"
    #session['ds_access_token']=token
    ok = "ds_access_token" in session and "ds_expiration" in session
    #print(ok)
    ok = ok and (session["ds_expiration"] - timedelta(minutes=buffer_min)) > datetime.utcnow()
    return ok


base_uri_suffix = "/restapi"
oauth = OAuth(app)
request_token_params = {"scope": "signature",
                        "state": lambda: uuid.uuid4().hex.upper()}
if not ds_config.DS_CONFIG["allow_silent_authentication"]:
    request_token_params["prompt"] = "login"
docusign = oauth.remote_app(
    "docusign",
    consumer_key=ds_config.DS_CONFIG["ds_client_id"],
    consumer_secret=ds_config.DS_CONFIG["ds_client_secret"],
    access_token_url=ds_config.DS_CONFIG["authorization_server"] + "/oauth/token",
    authorize_url=ds_config.DS_CONFIG["authorization_server"] + "/oauth/auth",
    request_token_params=request_token_params,
    base_url=None,
    request_token_url=None,
    access_token_method="POST"
)


@app.route("/ds/login")
def ds_login():
    return docusign.authorize(callback=url_for("ds_callback", _external=True))


@app.route("/ds/logout")
def ds_logout():
    ds_logout_internal()
    flash("You have logged out from DocuSign.")
    return redirect(url_for("index"))


def ds_logout_internal():
    # remove the keys and their values from the session
    session.pop("ds_access_token", None)
    session.pop("ds_refresh_token", None)
    session.pop("ds_user_email", None)
    session.pop("ds_user_name", None)
    session.pop("ds_expiration", None)
    session.pop("ds_account_id", None)
    session.pop("ds_account_name", None)
    session.pop("ds_base_path", None)
    session.pop("envelope_id", None)
    session.pop("eg", None)
    session.pop("envelope_documents", None)
    session.pop("template_id", None)


@app.route("/ds/callback")
def ds_callback():
    """Called via a redirect from DocuSign authentication service """
    # Save the redirect eg if present
    redirect_url = session.pop("eg", None)
    # reset the session
    ds_logout_internal()
    
    resp = docusign.authorized_response()
    #print("resp")
    #print(resp)
    if resp is None or resp.get("access_token") is None:
        return "Access denied: reason=%s error=%s resp=%s" % (
            request.args["error"],
            request.args["error_description"],
            resp
        )
    # app.logger.info("Authenticated with DocuSign.")
    flash("You have authenticated with DocuSign.")
    session["ds_access_token"] = resp["access_token"]
    session["ds_refresh_token"] = resp["refresh_token"]
    session["ds_expiration"] = datetime.utcnow() + timedelta(seconds=resp["expires_in"])

    # Determine user, account_id, base_url by calling OAuth::getUserInfo
    # See https://developers.docusign.com/esign-rest-api/guides/authentication/user-info-endpoints
    url = ds_config.DS_CONFIG["authorization_server"] + "/oauth/userinfo"
    auth = {"Authorization": "Bearer " + session["ds_access_token"]}
    response = requests.get(url, headers=auth).json()
    session["ds_user_name"] = response["name"]
    session["ds_user_email"] = response["email"]
    accounts = response["accounts"]
    account = None # the account we want to use
    # Find the account...
    target_account_id = ds_config.DS_CONFIG["target_account_id"]
    if target_account_id:
        account = next( (a for a in accounts if a["account_id"] == target_account_id), None)
        if not account:
            # Panic! The user does not have the targeted account. They should not log in!
            raise Exception("No access to target account")
    else: # get the default account
        account = next((a for a in accounts if a["is_default"]), None)
        if not account:
            # Panic! Every user should always have a default account
            raise Exception("No default account")

    # Save the account information
    session["ds_account_id"] = account["account_id"]
    session["ds_account_name"] = account["account_name"]
    session["ds_base_path"] = account["base_uri"] + base_uri_suffix

    if not redirect_url:
        redirect_url = url_for("index")
    return redirect(redirect_url)

# ################################################################################

@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template("500.html"), 500


@app.route("/ds_return")
def ds_return():
    event = request.args.get("event")
    state = request.args.get("state")
    envelope_id = request.args.get("envelopeId")
    return render_template("ds_return.html",
        title = "Return from DocuSign",
        event =  event,
        envelope_id = envelope_id,
        state = state
    )



if __name__ == '__main__':
    #app.config['SECRET_KEY']='demo'
    app.config['SESSION_PERMANENT'] = True
    app.config['SECRET_KEY'] = "hdfgu7sd6gfusghk7g34rhdkjshkfhskjdhfjsdhfjk"
    app.config['SESSION_TYPE'] = 'filesystem'
    # # app.config['SESSION_REDIS_PREFIX'] = 'app'
    # # app.config['SESSION_COOKIE_ID']='app-session-id',
    # # app.config['SESSION_COOKIE_HTTP_ONLY'] = True,
    # # app.config['SESSION_COOKIE_SECURE'] = False,
    # # app.config['SESSION_COOKIE_DOMAIN'] = '.mydomain.com',
    # # app.config['SESSION_COOKIE_PATH'] = '/',
    # # app.config['SESSION_EXPIRE']=60*60*24*7
    # # #app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
    #app.config['SESSION_FILE_THRESHOLD'] = 100  

    sess = Session()
    sess.init_app(app)
    app.run()
