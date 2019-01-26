#!/usr/bin/env python3

from database_setup import User, Category, Item, Base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, desc
from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import session as login_session, flash
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from functools import wraps

# client id from client.json 
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

# connect to the database
engine = create_engine('sqlite:///catagories.db?check_same_thread=False')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)


# check if already logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            return redirect('/login')
    return decorated_function


@app.route("/")
def showCategories():

    try:
        catagories = session.query(Category).all()
    except:
        response = make_response(json.dumps('Somthing went wrong 1'), 500)
        response.headers['content-type'] = 'application/json'
        return response
    try:
        items = session.query(Item).order_by(Item.id.desc()).limit(5).all()
    except:
        response = make_response(json.dumps('Somthing went wrong 2'), 500)
        response.headers['content-type'] = 'application/json'
        return response

    return render_template(
        "categories.html", catagories=catagories, headLine="Latest Items",
        items=items)


@app.route('/<int:category_id>')
def showItems(category_id):

    try:
        catagories = session.query(Category).all()
    except:
        response = make_response(json.dumps('Somthing went wrong 3'), 500)
        response.headers['content-type'] = 'application/json'
        return response
    try:
        items = session.query(Item).filter_by(category_id=category_id).all()
    except:
        response = make_response(json.dumps('Somthing went wrong 4'), 500)
        response.headers['content-type'] = 'application/json'
        return response
    try:
        category = session.query(Category).filter_by(
            id=category_id).one()
    except:
        response = make_response(json.dumps('Somthing went wrong 5'), 500)
        response.headers['content-type'] = 'application/json'
        return response

    return render_template(
        "categories.html", catagories=catagories, headLine=category.name,
        items=items)


@app.route('/<int:category_id>/<int:item_id>')
def item(category_id, item_id):

    try:
        item = session.query(Item).filter_by(id=item_id).one()
    except:
        response = make_response(json.dumps('Somthing went wrong 6'), 500)
        response.headers['content-type'] = 'application/json'
        return response


    # check user have the authority edit or delete

    stored_user_id = login_session.get("user_id")
    authorized = stored_user_id == item.user_id

    return render_template("item.html", item=item, authorized=authorized)


@app.route("/newItem", methods=["POST", "GET"])
@login_required
def newItem():

    if request.method == "POST":

        try:
            item = Item(
                name=request.form["name"],
                description=request.form["description"],
                category_id=request.form["catagories"],
                user_id=login_session["user_id"])
            session.add(item)
            session.commit()
            flash('New Item Successfully Created')
        except:
            response = make_response(json.dumps('Somthing went wrong 7'), 500)
            response.headers['content-type'] = 'application/json'
            return response

        return redirect(url_for('showCategories'))

    try:
        catagories = session.query(Category).all()
    except:
        response = make_response(json.dumps('Somthing went wrong 8'), 500)
        response.headers['content-type'] = 'application/json'
        return response

    return render_template('new_item.html', catagories=catagories)


@app.route('/<int:category_id>/<int:item_id>/edit', methods=["POST", "GET"])
@login_required
def editItem(category_id, item_id, methods=["POST", "GET"]):

    try:
        item = session.query(Item).filter_by(id=item_id).one()
    except:
        response = make_response(json.dumps('Somthing went wrong 9'), 500)
        response.headers['content-type'] = 'application/json'
        return response

    # check user have the authority to edit the item
    if login_session["user_id"] == item.user_id:

        if request.method == "POST":
            item.name = request.form["name"]
            item.description = request.form["description"]
            item.catagorie_id = request.form["catagories"]
            try:
                session.add(item)
                session.commit()
            except:
                response = make_response(
                    json.dumps('Somthing went wrong 9'), 500)
                response.headers['content-type'] = 'application/json'
                return response

            # send falsh successfully edited
            flash('Item Successfully Edited')
            return redirect(url_for('showCategories'))

        else:

            try:
                catagories = session.query(Category).all()
            except:
                response = make_response(
                    json.dumps('Somthing went wrong 10'), 500)
                response.headers['content-type'] = 'application/json'
                return response

            return render_template('edit_item.html', catagories=catagories)
    else:

        response = make_response(json.dumps('unauthorized'), 401)
        response.headers['content-type'] = 'application/json'
        return response


@app.route('/<int:category_id>/<int:item_id>/delete', methods=["POST", "GET"])
@login_required
def deleteItem(category_id, item_id, methods=["POST", "GET"]):

   
    try:
        item = session.query(Item).filter_by(id=item_id).one()
    except:
        response = make_response(json.dumps('Somthing went wrong 11'), 500)
        response.headers['content-type'] = 'application/json'
        return response

    # check user have the authority to delete 
    if login_session["user_id"] == item.user_id:

        if request.method == "POST":

            try:
                session.delete(item)
                session.commit()
            except:
                response = make_response(
                    json.dumps('Somthing went wrong 9'), 500)
                response.headers['content-type'] = 'application/json'
                return response

            # send flash successfully deleted
            flash('Item Successfully Deleted')
            return redirect(url_for('showCategories'))

        else:
            return render_template('delete_item.html')
    else:

       
        response = make_response(json.dumps('unauthorized'), 401)
        response.headers['content-type'] = 'application/json'
        return response


@app.route('/login')
def login():
  
    if 'username' not in login_session:

      
        state = ''.join(random.choice(string.ascii_uppercase +
                                      string.digits) for x in xrange(32))

      
        login_session['state'] = state

        
        return render_template('login.html', STATE=login_session['state'])
    else:

     
        flash('you were logged in')

        return redirect(url_for('showCategories'))


@app.route('/gconnect', methods=['POST'])
def gconnect():

   
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('invalid state token'), 401)
        response.headers['content-type'] = 'application/json'
        return response

    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('faild to'), 401)
        response.headers['content-type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
           access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        response = make_response(json.dumps('error'), 500)
        response.headers['content-type'] = 'application/json'

    gplus_id = credentials.id_token['sub']

    if result['user_id'] != gplus_id:
        response = make_response(json.dumps('token does not'), 401)
        response.headers['content-type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps('token c id does not match'), 401)
        response.headers['content-type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')

    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    login_session['provider'] = 'google'

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['picture'] = data['picture']

    user_id = getUserId(login_session['email'])
    if user_id is None:

        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    message = 'you logged in as %s' % login_session['username']
    flash(message)

    response = make_response(json.dumps(message), 200)
    response.headers['content-type'] = 'application/json'
    return response


@app.route('/logout')
def logout():

    if 'provider' in login_session:

        if login_session['provider'] == 'google':

            result = gdisconnect()
            if result != '200':
                flash('Failed to revoke token for given user.')
                return redirect(url_for('showCategories'))

            del login_session['gplus_id']

        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        del login_session['access_token']

        flash('Successfully logged out.')
        return redirect(url_for('showCategories'))
    else:
        flash('you were not logged in')
        return redirect(url_for('showCategories'))


@app.route('/JSON')
def showCategoriesAsJOSN():

    
    try:
        catagories = session.query(Category).all()
    except:
        response = make_response(json.dumps(
            'Somthing went wrong (JSON: 1)'), 500)
        response.headers['content-type'] = 'application/json'
        return response

    return jsonify(Category=[i.serialize for i in catagories])


@app.route('/<int:category_id>/JSON')
def showItemsAsJSON(category_id):

 
    try:
        items = session.query(Item).filter_by(category_id=category_id).all()
    except:
        response = make_response(json.dumps(
            'Somthing went wrong (JSON: 2)'), 500)
        response.headers['content-type'] = 'application/json'
        return response

   
    return jsonify(Item=[i.serialize for i in items])


@app.route('/<int:category_id>/<int:item_id>/JSON')
def itemAsJSON(category_id, item_id):

 
    try:
        item = session.query(Item).filter_by(id=item_id).one()
    except:
        response = make_response(json.dumps(
            'Somthing went wrong (JSON: 3)'), 500)
        response.headers['content-type'] = 'application/json'
        return response

   
    return jsonify(Item=item.serialize)

def gdisconnect():

    url = "https://accounts.google.com/o/oauth2/revoke?token="
    url += login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    return result['status']


def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserId(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

if __name__ == '__main__':
    app.secret_key = '**&**'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)