from flask.json import jsonify
from google.cloud import datastore
from flask import Flask, request, abort
import json
import constants

app = Flask(__name__)
client = datastore.Client()


@app.route('/')
def index():
    return "Please navigate to /boats to use this API"\



@app.route('/boats', methods=['POST', 'GET'])
def boats_get_post():
    if request.method == 'POST':
        content = request.get_json()
        if(len(content) != 3):
            return  {"Error": "The request object is missing at least one of the required attributes"} , 400
        new_boat = datastore.entity.Entity(
            key=client.key(constants.boats))
        new_boat.update({"name": content["name"], "type": content["type"],
                            "length": content["length"]})
        client.put(new_boat)
        new_boat.update({"id": new_boat.key.id, "self": str(request.base_url) + "/" + str(new_boat.key.id)})
        return jsonify(new_boat), 201
    elif request.method == 'GET':
        query = client.query(kind=constants.boats)
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id
            e["self"] =  str(request.base_url) + "/" + str(e.key.id)
        return jsonify(results)
    else:
        return 'Method not recognized'

@app.route('/boats/<id>', methods={'GET', 'PATCH', 'DELETE'})
def boat_get_patch_delete(id):
    if request.method == 'GET':
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if(boat is None):
            return {"Error": "No boat with this boat_id exists"}, 404
        boat['id'] = id
        boat["self"] = str(request.base_url)
        return json.dumps(boat), 200
    
    elif request.method == 'PATCH':
        content = request.get_json()
        if(len(content) !=3):
            return {"Error": "The request object is missing at least one of the required attributes"} , 400
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if(boat is None):
            return {"Error": "No boat with this boat_id exists"}, 404
        boat.update({"name": content["name"], "type": content["type"],
                            "length": content["length"]})
        client.put(boat)                    
        boat['id'] = id
        boat["self"] = str(request.base_url)
        return json.dumps(boat), 200
    
    elif request.method == "DELETE":
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if(boat is None):
            return {"Error": "No boat with this boat_id exists"}, 404
        # still need to clear the slip if a boat is deleted
        query = client.query(kind=constants.slips)
        results = list(query.fetch())
        for slip in results:
            if slip["current_boat"] == int(id):
                slip["current_boat"] = None
                client.put(slip)
        client.delete(boat_key)
        return ('', 204)
    
    else:
        return 'Method not recognized'

@app.route('/slips', methods=['POST', 'GET'])
def slips_get_post():
    if request.method == 'POST':
        content = request.get_json()
        if not "number" in content:
            return {"Error": "The request object is missing the required number"}, 400
        new_slip = datastore.entity.Entity(
        key=client.key(constants.slips))
        new_slip.update({"number": content["number"], "current_boat" : None })
        client.put(new_slip)
        new_slip.update({"id": new_slip.key.id, "self": str(request.base_url) + "/" + str(new_slip.key.id)})
        return jsonify(new_slip), 201
    
    elif request.method == 'GET':
        query = client.query(kind=constants.slips)
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id
            e["self"] =  str(request.base_url) + "/" + str(e.key.id)
        return json.dumps(results)
    
    else:
        return 'Method not recognized' 
    
@app.route('/slips/<id>', methods={'GET', 'DELETE'})
def slip_get_delete(id):
    if request.method == 'GET':
        slip_key = client.key(constants.slips, int(id))
        slip = client.get(key=slip_key)
        if(slip is None):
            return {"Error": "No slip with this slip_id exists"}, 404
        slip['id'] = int(id)
        slip["self"] = str(request.base_url)
        return json.dumps(slip), 200
    
    elif request.method == "DELETE":
        # still need to clear the slip if a boat is deleted
        slip_key = client.key(constants.slips, int(id))
        slip = client.get(key=slip_key)
        if(slip is None):
            return {"Error": "No slip with this slip_id exists"}, 404
        client.delete(slip_key)
        return ('', 204)
    
    else:
        return 'Method not recognized'

@app.route('/slips/<slip_id>/<boat_id>', methods=['PUT', 'DELETE'])
def boat_arrives_departs(slip_id, boat_id):
    if request.method == 'PUT':
        # check for valid slip
        slip_key = client.key(constants.slips, int(slip_id))
        slip = client.get(key=slip_key)
        if(slip is None):
            return {"Error": "The specified boat and/or slip does not exist"}, 404
        # check for valid boat
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        if(boat is None):
            return {"Error": "The specified boat and/or slip does not exist"}, 404
        
        if slip["current_boat"] is not None:
            return {"Error": "The slip is not empty"}, 403
        slip.update({"current_boat" : int(boat_id)})
        client.put(slip)
        return "", 204

    if request.method == 'DELETE':
        # check for valid slip
        slip_key = client.key(constants.slips, int(slip_id))
        slip = client.get(key=slip_key)
        if(slip is None):
            return {"Error": "No boat with this boat_id is at the slip with this slip_id"}, 404
        if slip["current_boat"] != int(boat_id):
            return {"Error": "No boat with this boat_id is at the slip with this slip_id"}, 404
        slip.update({"current_boat" : None})
        client.put(slip)
        return "", 204

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
