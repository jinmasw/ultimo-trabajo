#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import re
from google.appengine.api import users
from google.appengine.ext import ndb
from webapp2_extras import sessions
import session_module


INICIO = '''\
<!doctype html>
<html>
<head>

	<title> Inicio </title>

</head>
	<body>
		Buenas, que desea

		</br>

		<a href = "/registro"> Registro <a>

		</br>

		<a href = "/login"> Login <a>
	
	</body>
</html>	

'''

LOGIN = '''
<!doctype html>
<html>
<head>

	<title> Login </title>

</head>

	
	<body>
		
		<h1> Iniciar sesion </h1>
	
		<form method="post">
		
			Nombre de usuario: <input type= "text"
					name="nombre"
					id="nombre"
					value="%(nombre)s"/>
							
					
					<br/>
					<br/>
				
			Password: <input type= "password"
					name="password"
					id="password"
					value="%(password)s"/>
					
					<br/>
					<br/>
					
						
			<input type="submit" value= "Iniciar sesion" />
				
		</form>	
	
	</body>

</html>	

'''

REGISTRO = '''<!DOCTYPE html>
    <html lang="es">
         <head>
              <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
              <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0"/>
              <style type="text/css"> .label {text-align: right} .error {color: red} </style>
              <title>Registro</title>
         </head>
            <body>
                <div align="center">
                  <h1>Registro de Usuarios</h1>
                  <form method="post">
                    <table>
                        <tr>
                            <td class="label"> Nombre de usuario </td>
                            <td> <input type="text" name="username"  value="%(username)s" placeholder="Tu nombre...">
                            <td class="error"> %(username_error)s </td>
                         </tr>
                         <tr>
                            <td class="label"> Password </td>
                            <td> <input type="password" name="password" value="%(password)s" autocomplete="off" placeholder="Tu password..."></td>
                            <td class="error"> %(password_error)s </td>
                        </tr>
                        <tr>
                            <td class="label"> Repetir Password </td>
                            <td> <input type="password" name="verify" value="%(verify)s" placeholder="Repetir password...">
                            <td class="error"> %(verify_error)s </td>
                        </tr>
                        <tr>
                            <td class="label"> Email </td>
                            <td> <input type="text" name="email" value="%(email)s" placeholder="Tu email..."></td>
                            <td class="error"> %(email_error)s </td>
                        </tr>
                    </table> <input type="submit" name="Registrarse"> 
                  </form>
                </div>
            </body>
    </html>'''



INSERTAR = '''
<!doctype html>
<html>
<head>

	<title> Insertar pregunta </title>

</head>

	
	<body>
		
		<h1> Inserte una pregunta nueva </h1>
	
		<form  method="post">
		
			Enunciado: <input type= "text"
					name="enunciado"
					id="enunciado"
					value="%(enunciado)s"/>
					
					<br/>
					<br/>
				
			Opcion 1: <input type= "text"
					name="uno"
					id="uno"
					value="%(uno)s"/>
					
					<br/>
					<br/>

			Opcion 2: <input type= "text"
					name="dos"
					id="dos"
					value="%(dos)s"/>
					
					<br/>
					<br/>
			
			Opcion 3: <input type= "text"
					name="tres"
					id="tres"
					value="%(tres)s"/>
					
					<br/>
					<br/>		
			
			Numero de la opcion correcta: <input type= "number"
					name="buena"
					id="buena"
					value="%(buena)s"/>
					
					<br/>
					<br/>

			<input type="submit" value= "Insertar pregunta" />
				
		</form>	
	
	</body>

</html>	

'''




def escape_html(s):
    return cgi.escape(s, quote=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASSWORD_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

class registroHandler(session_module.BaseSessionHandler):
    def write_form(self, username="", password="", verify="",
                   email="", username_error="", password_error="",
                   verify_error="", email_error=""):
        self.response.write(REGISTRO % {"username":username,
                                        "password": password,
                                        "verify": verify,
                                        "email": email,
                                        "username_error": username_error,
                                        "password_error": password_error,
                                        "verify_error": verify_error,
                                        "email_error": email_error})

    def get(self):
        self.write_form()

    def post(self):
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')
        sani_username = escape_html(user_username)
        sani_password = escape_html(user_password)
        sani_verify = escape_html(user_verify)
        sani_email = escape_html(user_email)
        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""

        error = False
        if not valid_username(user_username):
            username_error = "Nombre incorrecto!"
            error = True
        if not valid_password(user_password):
            password_error = "Password incorrecto!"
            error = True
        if not user_verify or not user_password == user_verify:
            verify_error = "Password no coincide!"
            error = True
        if not valid_email(user_email):
            email_error = "Email incorrecto!"
            error = True

        if error:
            self.write_form(sani_username, sani_password, sani_verify, sani_email, username_error, password_error,
                            verify_error, email_error)
        else:
            user = Usuario.query(Usuario.nombre == user_username,
                                 Usuario.email == user_email).count()
            if user == 0:
                u = Usuario()
                u.nombre = user_username
                u.email = user_email
                u.password = user_password
                u.put()
                self.session['email']=user_email
                self.response.write(INICIO)
            else:
                self.write_form(sani_username, sani_password, sani_verify, sani_email, username_error, password_error,
                                verify_error, email_error)
                self.response.out.write("Hola: %s <p> Ya estabas registrado" % user_username)

class visualizar(webapp2.RedirectHandler):
    def get(self):
        preguntas = Pregunta.query()
        self.response.out.write('<h1 align="center">Preguntas</h1>')
        for p in preguntas:
                self.response.out.write("%s <br/>" % p.enunciado)

class loginHandler(session_module.BaseSessionHandler):
    def write_form(self, password="", nombre=""):

        self.response.write(LOGIN % {"password": password,
                                    "nombre": nombre})
    def get(self):
        self.write_form()

    def post(self):
        user_password = self.request.get('password')
        user_name = self.request.get('nombre')

        user = Usuario.query(Usuario.nombre == user_name, Usuario.password == user_password).count()
        if user != 0:
            self.session['name']=user_name
            self.response.out.write("nombre: %s" % user_name)
            self.response.out.write("<br/>")
            self.response.out.write("pass: %s" % user_password)
            self.response.out.write("<br/>")
            self.response.out.write("<br/>")
            self.response.out.write("<a href = '/insertar'> Insertar pregunta <a>")
            self.response.out.write("<a href = '/visualizar'> Ver preguntas <a>")
        else:
            self.response.out.write("Hola: %s <p> no estas registrado" % user_name)



class insertarNueva(session_module.BaseSessionHandler):
	def write_form(self, enunciado="", uno="", dos="", tres="", buena=""):
		self.response.write(INSERTAR % {"enunciado" : enunciado,
											"uno" : uno,
											"dos" : dos,
											"tres" : tres,
											"buena" : buena})

	def get(self):
		self.write_form()

	def post(self):

		enunciado = self.request.get('enunciado') 
		o1 = self.request.get('uno')
		o2 = self.request.get('dos')
		o3 = self.request.get('tres')
		correcta = self.request.get('buena')
		creador = self.session['name']
		pregunta = Pregunta()
		pregunta.enunciado = enunciado
		pregunta.respuesta1 = o1 
		pregunta.respuesta2 = o2
		pregunta.respuesta3 = o3
		pregunta.numero_correcta = int(correcta)
		pregunta.usuario_creador = creador 

		pregunta.put()
		self.response.out.write("Pregunta insertada")



class Usuario(ndb.Model):
	nombre=ndb.StringProperty()
	email=ndb.StringProperty()
	password=ndb.StringProperty(indexed=True)


class Pregunta(ndb.Model):
	enunciado = ndb.StringProperty()
	respuesta1 = ndb.StringProperty()
	respuesta2 = ndb.StringProperty()
	respuesta3 = ndb.StringProperty()
	numero_correcta = ndb.IntegerProperty()
	usuario_creador = ndb.StringProperty()


class inicioHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write(INICIO)
       

app = webapp2.WSGIApplication([
    ('/', inicioHandler),
   	('/registro', registroHandler),
   	('/login', loginHandler),
   	('/insertar', insertarNueva),
   	('/visualizar', visualizar)
   	],
   	config = session_module.myconfig_dict,
debug=True)