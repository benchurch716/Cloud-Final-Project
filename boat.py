from flask.json import jsonify
from google.cloud import datastore
from flask import Flask, Blueprint, request
import constants

client = datastore.Client()

bp = Blueprint('boat', __name__, url_prefix='/boats')

@bp.route('', methods=['POST', 'GET'])
def boats_get_post():
    if request.method == 'POST':
        content = request.get_json()
        if(len(content) != 3):
            return  {"Error": "The request object is missing at least one of the required attributes"} , 400
        new_boat = datastore.entity.Entity(
            key=client.key(constants.boats))
        new_boat.update({"name": content["name"], "type": content["type"],
                            "length": content["length"], "loads": []})
        client.put(new_boat)
        new_boat.update({"id": new_boat.key.id, "self": str(request.base_url) + "/" + str(new_boat.key.id)})
        return jsonify(new_boat), 201
    
    # adapted from Exploration - Intermediate REST API Features with Python
    elif request.method == 'GET': 
        query = client.query(kind=constants.boats)
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
        output = {"boats": results}
        if next_url:
            output["next"] = next_url
        return jsonify(output)
    else:
        return 'Method not recogonized'

@bp.route('/<id>', methods={'GET', 'PATCH', 'DELETE'})
def boat_get_patch_delete(id):
    if request.method == 'GET':
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if(boat is None):
            return {"Error": "No boat with this boat_id exists"}, 404
        boat['id'] = id
        boat["self"] = str(request.base_url)
        return jsonify(boat), 200
    
    elif request.method == "DELETE":
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if(boat is None):
            return {"Error": "No boat with this boat_id exists"}, 404
        # clear the load if a boat is deleted
        query = client.query(kind=constants.loads)
        results = list(query.fetch())
        for load in results:
            if load["carrier"] is not None:
                if load["carrier"]["id"] == int(id):
                    load["carrier"] = None
                    client.put(load)
        client.delete(boat_key)
        return ('', 204)
    
    else:
        return 'Method not recognized'

@bp.route('/<id>/loads', methods={'GET'})
def get_all_loads(id):
    # retrive the boat
    boat_key = client.key(constants.boats, int(id))
    boat = client.get(key=boat_key)
    # check for valid boat
    if(boat is None):
        return {"Error": "No boat with this boat_id exists"}, 404
    # return all loads
    return jsonify(boat["loads"]), 200 
    

@bp.route('/<boat_id>/loads/<load_id>', methods=['PUT', 'DELETE'])
def add_remove_load(load_id, boat_id):
    if request.method == 'PUT':
        # check for valid load
        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)
        if(load is None):
            return {"Error": "The specified boat and/or load does not exist"}, 404
        # check for valid boat
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        if(boat is None):
            return {"Error": "The specified boat and/or load does not exist"}, 404
        # check for load not in use
        if load["carrier"] is not None:
            return {"Error": "The load is already on a ship" }, 403
        # update loads with carrier
        load.update({"carrier" : {"id": int(boat_id), "name": boat["name"], "self": str(request.url_root) + "boats/" + str(boat.key.id)}})
        client.put(load)
        # update boat with load
        boat["loads"].append({"id": int(load_id), "self": str(request.url_root) + "loads/" + str(load.key.id)})
        client.put(boat)
        return "", 204

    if request.method == 'DELETE':
        # check for valid load
        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)
        if(load is None):
            return {"Error": "No load with this load_id"}, 404
        # check for valid boat
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        if(boat is None):
            return {"Error": "No boat with this boat_id"}, 404
        # search the list of loads
        for item in boat["loads"]:
            if item["id"] == int(load_id):
                # remove the load from the boat
                boat["loads"].remove(item)
                client.put(boat)
                # set the load carrier to null
                load.update({"carrier" : None})
                client.put(load)
                return "", 204
        return  {"Error": "No load with this load_id is on this boat with this boat_id"}, 404