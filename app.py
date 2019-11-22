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
#import cv2
#import numpy as np
from flask import Flask, session
from reportlab.pdfgen import canvas
#from PyPDF2 import PdfFileWriter, PdfFileReader
import fitz
from io import StringIO
import urllib.request
from flask_session.__init__ import Session

#app = Flask(__name__)

# Uploads
# UPLOADS_DEFAULT_DEST = '/project/static/pdf/'
# UPLOADS_DEFAULT_URL = 'http://localhost:5000/static/pdf/'
 
# UPLOADED_IMAGES_DEST = 'static/img/'
# UPLOADED_IMAGES_URL = 'http://localhost:5000/static/img/'

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
    #print(qrlink)
    b=json.dumps(data['qrImage'])
    base64src1=json.dumps(data['qrImage'])
    #print(b)
    arr = []
    arr = b.split(',')
    b1 = arr[1]
    base64src1= base64src1.replace(".png","png")
    base64src1=base64src1.strip('"')
    #print(base64src1)
    session['base64str'] = base64src1
    #d1 = session.get('base64str')
    #print(d1)
    image = base64.b64decode(str(b1))

    # target = os.path.join(APP_ROOT, '/images')
    # file_name = uuid.uuid4().hex[:50].upper()
    # fileExtension = '.png'
    # file_name += fileExtension
    # image_path = file_name
    # im = Image.open(io.BytesIO(image))
    # newsize = (100, 100) 
    # im1 = im.resize(newsize)
    #     #im1.save('/tmp/'+image_path)
    # destination = "/".join([target, file_name])
    
    # im1.save(destination)
    # #upload.save()  
    return base64src1

    
    # nparr = np.fromstring(image.decode('base64'), np.uint8)
    # imggg = cv2.imdecode(nparr, cv2.IMREAD_ANYCOLOR)
    # cv2.imwrite(file_name, imggg)
    # #im1.save('/tmp/'+image_path)
    #im1.save(image_path)
    #print(file_name)

    #images.save(im1)
    #return send_file(file_name, mimetype='image/png')

@app.route('/uploader', methods = ['GET', 'POST'])
def upload_file1():
    if request.method == 'POST':
        filename = pdf.save(request.files['file'])
        session['path'] = pdf.path(filename)
        #print(filename.)
        url1 = pdf.url(filename)
        base64 = generateqr()
        session['base64'] = base64
        session['pdfurl']=url1
        print(APP_ROOT)
        #filename2 = photos.save(request.files['image'])
        #url2 = photos.url(filename2)
        #qr = generateqr()
        #print(qr)
        return render_template("index.html",file_path=url1,base64 = base64)

@app.route('/savefile', methods = ['GET', 'POST'])
def savefile():
    if request.method == 'POST':
        hd_topValue = request.form.get('hd_topValue')
        hd_leftValue =request.form.get('hd_leftValue')
        hd_pageNumber =request.form.get('hd_pageNumber')
        b=session.get('base64')
        arr = []
        arr = b.split(',')
        b1 = arr[1]
        b1= b1.replace(".png","png")
        b1=b1.strip('"')
        image = base64.b64decode(str(b1))
        im = Image.open(io.BytesIO(image))
        src_pdf_filename = session.get('path')#"static/download.pdf"#
        dst_pdf_filename = 'static/destination.pdf'
        print("before")
        print(src_pdf_filename)
        print(APP_ROOT)
        src_pdf_filename=src_pdf_filename.replace(APP_ROOT,'')
        print("After")
        print(src_pdf_filename)

        remoteFile = urllib.request.urlopen(session.get('pdfurl')).read()
        
        document = fitz.open(stream=remoteFile,filetype='pdf')
        # input1 = PdfFileReader(open(src_pdf_filename, 'rb'))
        # print(input1.getPage(1).mediaBox)
        # page1=input1.getPage(1)
        # pagelenght=page1.__len__()
        # print("page length")
        # print(pagelenght)
        # #len1 = pagelenght-hd_topValue-200
        #print(len1)
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
