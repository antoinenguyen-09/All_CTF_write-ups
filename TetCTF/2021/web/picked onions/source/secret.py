#!/usr/bin/python3
import json
import boto3
import base64
import pickle
from flask import *

app = Flask(__name__)

@app.route('/')
def index():
        return render_template('index.html')

@app.route('/login',methods=["GET","POST"])
def login():
        if request.method=="POST":
                return render_template('login.html',msg='Invalid Credentials')
        else:
                return render_template('login.html',msg='')

@app.route('/secret')
def env():
    return render_template('secret.html')

@app.route('/services')
def services():
        return render_template('services.html')

@app.route('/customers')
def customers():
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1',aws_access_key_id='AKIAXNIS54OCBQD5C4ME',aws_secret_access_key='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',region_name="us-east-1")
        table = dynamodb.Table('customers')
        response = table.scan()
        data=[]
        for i in response["Items"]:
                print (i)
                i=base64.b64decode(i["data"])
                i=pickle.loads(i)
                print (i)
                data.append(i)
        return render_template('customers.html',data=data)

app.run('0.0.0.0',9000)
