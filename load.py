from flask.json import jsonify
from google.cloud import datastore
from flask import Flask, Blueprint, request
import constants

client = datastore.Client()

bp = Blueprint('load', __name__, url_prefix='/loads')

@bp.route('', methods=['POST', 'GET'])
def loads_get_post():
    if request.method == 'POST':
        content = request.get_json()
        if (len(content) != 3):
            return {"Error": "The request object is missing the required number"}, 400
        new_load = datastore.entity.Entity(
        key=client.key(constants.loads))
        new_load.update({"volume": content["volume"], "content" : content["content"], "creation_date": content["creation_date"], "carrier": None })
        client.put(new_load)
        new_load.update({"id": new_load.key.id, "self": str(request.base_url) + "/" + str(new_load.key.id)})
        return jsonify(new_load), 201
    
    # adapted from Exploration - Intermediate REST API Features with Python
    elif request.method == 'GET': 
        query = client.query(kind=constants.loads)
        q_limit = int(request.args.get('limit', '3'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
        output = {"loads": results}
        if next_url:
            output["next"] = next_url
        return jsonify(output)
    else:
        return 'Method not recogonized' 
    
@bp.route('/<id>', methods={'GET', 'DELETE'})
def load_get_delete(id):
    if request.method == 'GET':
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        if(load is None):
            return {"Error": "No load with this load_id exists"}, 404
        load['id'] = int(id)
        load["self"] = str(request.base_url)
        return jsonify(load), 200
    
    elif request.method == "DELETE":
        # check if load exists
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        if(load is None):
            return {"Error": "No load with this load_id exists"}, 404
        # Remove load from the boat
        query = client.query(kind=constants.boats)
        results = list(query.fetch())
        # search through boats
        for boat in results:
            for load in boat["loads"]:
                if load["id"] == int(id):
                    boat["loads"].remove(load)
                    client.put(boat)
                    break
        # delete the load
        client.delete(load_key)
        return ('', 204)
    
    else:
        return 'Method not recognized'

        
