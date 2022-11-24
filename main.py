from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


import json
import requests
import datetime
import re
from waitress import serve


app=Flask(__name__)
cors = CORS(app)

app.config["JWT_SECRET_KEY"]="super-secret"
jwt = JWTManager(app)

@app.before_request
def middleware():
    urlAcceso = request.path
    if(urlAcceso == "/login"):
        pass
    else:

        if(verify_jwt_in_request()):
            infoUsuario = get_jwt_identity()
            idRol = infoUsuario["rol"]["_id"]
            print("rol del usuario es: ", idRol)

            urlAcceso = transformarUrl(urlAcceso)

            urlValidarpermiso = dataConfig["url-backend-security"] + "/permisos-rol/validar-permiso/rol/" + idRol
            headersValidarpermiso = {"Content-Type": "application/json"}
            bodyValidarpermiso = {
                "url": urlAcceso,
                "metodo": request.method
            }
            respuestaValidarpermiso = requests.get(urlValidarpermiso, json=bodyValidarpermiso,
                                                   headers=headersValidarpermiso)
            print("respuesta validar permiso: ", respuestaValidarpermiso)

            if (respuestaValidarpermiso.status_code == 200):
                pass
            else:
                return {"mensaje ": "Acceso denegado"}, 401





def transformarUrl(urlAcceso):
    print("url antes : ",urlAcceso)

    partesUrl= urlAcceso.split("/")
    print("partes url: "+str(partesUrl))

    for palabra in partesUrl:
        if re.search('\\d',palabra):
            urlAcceso = urlAcceso.replace(palabra,"?")

    print("urldespues de transformarla..:", urlAcceso)
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


#path candidato
@app.route("/candidato", methods=['POST'])
def crearCandidato():
    url = dataConfig["url-backend-registraduria"] + "/candidato"
    headers = {"Content-Type": "application/json"}
    body = request.get_json()

    response = requests.post(url, json=body, headers=headers)

    return response.json()

@app.route("/candidato/<string:idObject>", methods=['GET'])
def buscarCandidato(idObject):
    url = dataConfig["url-backend-registraduria"] + "/candidato" + idObject
    headers = {"Content-Type": "application/json"}


    response = requests.get(url, headers=headers)

    return response.json()

@app.route("/candidato", methods=['GET'])
def buscarTodosLosCandidatos():
    url= dataConfig["url-backend-registraduria"] + "/candidato"
    headers = {"Content-Type": "application/json"}

    response=requests.get(url,headers=headers)

    return response.json()

@app.route("/candidato/<string:id>", methods=['PUT'])
def actualizarCandidato(id):
    url= dataConfig["url-backend-registraduria"] + "/candidato" + id
    headers= {"Content-Type": "application/json"}
    body= request.get_json()

    response=requests.put(url,json=body, headers=headers)

    return response.json()

#relacion uno a muchos

@app.route("/candidato/<string:idCandidato>/partido/<string:id_Partido>",methods=['PUT'])
def asignarPartido(idCandidato,id_Partido):
    url= dataConfig["url-backend-registraduria"] + "/candidato" + idCandidato + "/partido" + id_Partido
    headers= {"Content-Type": "application/json"}

    response=requests.put(url,headers=headers)

    return response.json()

@app.route("/candidato/<string:idObject>", methods=['DELETE'])
def eliminarCandidato(idObject):
    url= dataConfig["url-backend-registraduria"] + "/candidato" + idObject
    headers= {"Content-Type": "application/json"}

    response= requests.delete(url, headers=headers)

    return response.json()

#path Mesa

@app.route("/mesa",methods=['POST'])
def crearMesa():
    url= dataConfig["url-backend-registraduria"] + "/mesa"
    headers= {"Content-Type": "application/json"}
    body= request.get_json()

    response=requests.post(url,json=body, headers=headers)

    return response.json()

@app.route("/mesa/<string:idMesa>",methods=['GET'])
def buscarMesa(idMesa):
    url= dataConfig["url-backend-registraduria"] + "/mesa" + idMesa
    headers = {"Content-Type": "application/json"}

    response=requests.get(url,headers=headers)

    return response.json()

@app.route("/mesa",methods=['GET'])
def buscarTodasLasMesas():
    url= dataConfig["url-backend-registraduria"] + "/mesa"
    headers= {"Content-Type": "application/json"}

    response=requests.get(url, headers=headers)

    return response.json()

@app.route("/mesa/<string:idMesa>", methods=['PUT'])
def actualizarMesa(idMesa):
    url= dataConfig["url-backend-registraduria"] + "/mesa" + idMesa
    headers= {"Content-Type": "application/json"}
    body=request.get_json()

    response=requests.put(url, json=body, headers=headers)

    return response.json()

@app.route("/mesa/<string:idMesa>", methods=['DELETE'])
def eliminarMesa(idMesa):
    url= dataConfig["url-backend-registraduria"] + "/mesa" + idMesa
    headers= {"Content-Type": "application/json"}

    response= requests.delete(url, headers=headers)

    return response.json()

#path de Partido
@app.route("/partidos",methods=['POST'])
def crearPartido():
    url= dataConfig["url-backend-registraduria"] + "/partidos"
    headers= {"Content-Type": "application/json"}
    body= request.get_json()

    response=requests.post(url, json=body, headers=headers)

    return response.json()

@app.route("/partidos/<string:id>",methods=['GET'])
def buscarPartido(id):
    url = dataConfig["url-backend-registraduria"] + "/partidos" + id
    headers= {"Content-Type": "application/json"}

    response= requests.get(url,headers=headers)

    return response.json()

@app.route("/partidos",methods=['GET'])
def buscarTodosLosPartidos():
    url= dataConfig["url-backend-registraduria"] + "/partidos"
    headers= {"Content-Type": "application/json"}

    response=requests.get(url,headers=headers)

    return response.json()

@app.route("/partidos/<string:idPartido>", methods=['PUT'])
def actualizarPartido(idPartido):
    url = dataConfig["url-backend-registraduria"] + "/partidos" + idPartido
    headers={"Content-Type": "application/json"}
    body= request.get_json()

    response=requests.put(url,json=body ,headers=headers)

    return response.json()

@app.route("/partidos/<string:id>",methods=['DELETE'])
def eliminarPartido(id):
    url = dataConfig["url-backend-registraduria"] + "/partidos" + id
    headers = {"Content-Type": "application/json"}

    response=requests.delete(url,headers=headers)

    return response.json()

#path Resultado con relacion muchos a muchos

@app.route("/resultado/candidato/<string:idCandidato>/mesa/<string:idMesa>", methods=['POST'])
def crearResultado(idCandidato, idMesa):
    url=dataConfig["url-backend-registraduria"] + "/resultado/candidato/" + idCandidato + "/mesa"+ idMesa
    headers = {"Content-Type": "application/json"}
    body= request.get_json()

    response=requests.post(url,json=body, headers=headers)

    return response.json()

@app.route("/resultado/<string:idObject>",methods=['GET'])
def buscarResultado(idObject):
    url=dataConfig["url-backend-registraduria"] + "/resultado" + idObject
    headers = {"Content-Type": "application/json"}

    response=requests.get(url,headers=headers)

    return response.json()

@app.route("/resultado",methods=['GET'])
def buscarTodosLosResultados():
    url=dataConfig["url-backend-registraduria"] + "/resultado"
    headers= {"Content-Type": "application/json"}

    response=requests.get(url, headers=headers)

    return response.json()

@app.route("/resultado/<string:idResultado>",methods=['PUT'])
def actualizarResultado(idResultado):
    url = dataConfig["url-backend-registraduria"] + "/resultado" + idResultado
    headers={"Content-Type": "application/json"}
    body=request.get_json()

    response=requests.put(url,json=body, headers=headers)

    return response.json()

@app.route("/resultado/<string:idObject>",methods=['DELETE'])
def eliminarResultado(idObject):
    url=dataConfig["url-backend-registraduria"] + "/resultado" + idObject
    headers = {"Content-Type": "application/json"}

    response=requests.delete(url, headers=headers)

    return response.json()



def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data

if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running: http://"+ dataConfig['url-backend'] + ":" + str(dataConfig['port']))
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])

