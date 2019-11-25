"""Flask App Project."""

from flask import Flask, jsonify
from flask import render_template, url_for, redirect, session, flash, request
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

app = Flask(__name__, instance_relative_config=True)

app.secret_key = os.urandom(24)

app.config['UPLOADED_DEFAULT_DEST'] = '/var/uploads'

#upload set configurations
pdf = UploadSet(extensions=('pdf','txt', 'rtf', 'odf', 'ods', 'gnumeric', 'abw', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpe', 'jpeg', 'png', 'gif', 'svg', 'bmp', 'csv', 'ini', 'json', 'plist', 'xml', 'yaml', 'yml'), default_dest=lambda app: app.instance_path)
configure_uploads(app, pdf)


APP_ROOT = os.path.dirname(os.path.abspath(__file__))


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
        return send_file(dst_pdf_filename)


if __name__ == '__main__':
    app.config['SESSION_TYPE'] = 'filesystem'
    app.run(debug=True)
