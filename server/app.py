#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        if 'username' not in data:
            return {'error': 'Username is required'}, 422
        new_user = User(
            username=data['username'],
            image_url=data.get('image_url', ''),
            bio=data.get('bio', '')
        )
        new_user.password_hash = data['password']
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return {'error': 'Username already exists.'}, 422
        session['user_id'] = new_user.id
        return new_user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter_by(id=user_id).first()
            if user:
                return user.to_dict(), 200
        return {'error': 'Unauthorized'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        else:
            return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete (self):
        if session.get('user_id'):
            session.pop('user_id',None)
            return {'message': 'Successfully logged out'}, 200
        else:
            return {'error': 'Unauthorized'}, 401
    

class RecipeIndex(Resource):
    def get(self):
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401
        
        recipes = Recipe.query.all()
        return [
            {
                'id': recipe.id,
                'title': recipe.title,
                'instructions': recipe.instructions,
                'minutes_to_complete': recipe.minutes_to_complete,
                'user_id': recipe.user_id
            } for recipe in recipes
        ], 200

    def post(self):
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401
        
        data = request.get_json()
        
        try:
            new_recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=session['user_id']
            )
            db.session.add(new_recipe)
            db.session.commit()
            return {
                'id': new_recipe.id,
                'title': new_recipe.title,
                'instructions': new_recipe.instructions,
                'minutes_to_complete': new_recipe.minutes_to_complete,
                'user_id': new_recipe.user_id
            }, 201
        except ValueError as e:
            return {'errors': [str(e)]}, 422
        except KeyError as e:
            return {'errors': [f'Missing required field: {str(e)}']}, 422
        except IntegrityError:
            db.session.rollback()
            return {'errors': ['Validation errors']}, 422
        

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)