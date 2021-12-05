from flask.json import jsonify
from google.cloud import datastore
from flask import Flask, Blueprint, request
import constants

client = datastore.Client()

bp = Blueprint('user', __name__, url_prefix='/users')

@bp.route('', methods=['POST', 'GET'])
def user_get_post():