

from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS


import json
import requests
import datetime
import re
from waitress import serve


app=Flask(__name__)

from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
app.config["JWT_SECRET_KEY"]="super-secret"
jwt = JWTManager(app)

@app.before_request
def middleware():
    urlAcceso = request.path
    if(urlAcceso == "/login"):
        pass
    else:

        verify_jwt_in_request()

        infoUsuario = get_jwt_identity()
        idRol = infoUsuario["rol"]["_id"]
        print("rol del usuario es: ", idRol)

        urlAcceso=transformarUrl(urlAcceso)

        urlValidarpermiso = dataConfig["url-backend-security"] + "/permisos-rol/validar-permiso/rol/" + idRol
        headersValidarpermiso = {"Content-Type": "application/json"}
        bodyValidarpermiso = {
            "url": urlAcceso,
            "metodo": request.method
        }
        respuestaValidarpermiso = requests.get(urlValidarpermiso, json=bodyValidarpermiso,headers=headersValidarpermiso)
        print("respuesta validar permiso: ", respuestaValidarpermiso)

        if (respuestaValidarpermiso.status_code == 200):
            pass
        else:
            return {"mensaje ": "Acceso denegado"},401


def transformarUrl(urlAcceso):
    print("url antes : ",urlAcceso)

    partesUrl= urlAcceso.split("/")
    print("partes url: "+str(partesUrl))

    for palabra in partesUrl:
        if re.search('\\d',palabra):
            urlAcceso = urlAcceso.replace(palabra,"?")

    print("urldespues de transformarla:", urlAcceso)
    return urlAcceso


@app.route("/login",methods=['POST'])
def autenticarUsuario():


    url= dataConfig["url-backend-security"] + "/usuario/validar-usuario"
    bodyRequest= request.get_json()
    headers={
        "Content-Type": "application/json"
    }

    response =requests.post(url, json=bodyRequest, headers=headers)
    print("Respuesta del servicio: ", response)

    if(response.status_code == 200):

        print("Login Exitoso")

        usuarioInfo= response.json()
        tiempoCaducidadToken= datetime.timedelta(seconds=60*60)

        token = create_access_token(identity=usuarioInfo,expires_delta=tiempoCaducidadToken)
        return {"token": token}


    else:
        return {"mensage": "Ususario o contraseña Erroneos"}, 401


@app.route("/estudiante", methods=["POST"])
def crearEstudiante():
        url = dataConfig["url-backend-academic"] + "/estudiante"
        headers = {"Content-Type": "application/json"}
        body = request.get_json()

        response = requests.post(url, json=body, headers=headers)

        return response.json()

@app.route("/estudiante/<string:idObject>", methods=['GET'])
def buscarEstudiante(idObject):
    url = dataConfig["url-backend-academic"] + "/estudiante"+ idObject
    headers = {"Content-Type": "application/json"}


    response = requests.get(url, headers=headers)

    return response.json()



def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data

if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running: http://"+ dataConfig['url-backend'] + ":" + str(dataConfig['port']))
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])

