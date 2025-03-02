from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from cs50 import SQL
from flask import Flask, jsonify, render_template


from functools import wraps

import os


import smtplib
import email.message

UPLOAD_FOLDER = "static/imgs"  # Define a pasta correta
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Garante que a pasta existe

def get_next_filename(extension):
    """Encontra o próximo número disponível para salvar o arquivo"""
    existing_files = [int(f.split('.')[0]) for f in os.listdir(UPLOAD_FOLDER) if f.split('.')[0].isdigit()]
    next_number = max(existing_files) + 1 if existing_files else 1  # Se não houver arquivos, começa em 1
    return f"{next_number}{extension}"


def enviar_email(corpo_email):  
    

    msg = email.message.Message()
    msg['Subject'] = "Assunto"
    msg['From'] = 'caioba.maciel@gmail.com'
    msg['To'] = 'caioba.maciel@gmail.com'
    password = 'nqtenlurghflcokf'
    msg.add_header('Content-Type', 'text/html')
    msg.set_payload(corpo_email )

    s = smtplib.SMTP('smtp.gmail.com: 587')
    s.starttls()
    # Login Credentials for sending the mail
    s.login(msg['From'], password)
    s.sendmail(msg['From'], [msg['To']], msg.as_string().encode('utf-8'))
    print('Email enviado')


def EmailToClient(corpo_email, client):  
    

    msg = email.message.Message()
    msg['Subject'] = "Assunto"
    msg['From'] = 'caioba.maciel@gmail.com'
    msg['To'] = client
    password = 'nqtenlurghflcokf'
    msg.add_header('Content-Type', 'text/html')
    msg.set_payload(corpo_email )

    s = smtplib.SMTP('smtp.gmail.com: 587')
    s.starttls()
    # Login Credentials for sending the mail
    s.login(msg['From'], password)
    s.sendmail(msg['From'], [msg['To']], msg.as_string().encode('utf-8'))
    print('Email enviado')



# In[ ]:

app = Flask(__name__)

# Configuração da sessão
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)



def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function
# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///ads.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response




@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    return redirect("/mypage")



@app.route("/explore", methods=["GET", "POST"])
@login_required
def explore():
    return "explorar"



@app.route("/mypage", methods=["GET", "POST"])
@login_required
def mypage():
    if request.method == "POST":

        if "delete" in request.form:
            db.execute("DELETE FROM ads WHERE user_id = ?", session["user_id"])

        if "image" in request.files:

            description = request.form.get("descripition")

            link = request.form.get("link")

            file = request.files["image"]

            print(link, description)

            if not description or not link:
                return("<h1>preencha o relatório corretamente</h1>")

            if file.filename == "":
                return "Nenhum arquivo selecionado."

            # Obtém a extensão do arquivo (.jpg, .png, etc.)
            ext = os.path.splitext(file.filename)[1]

            # Gera o próximo nome disponível
            new_filename = get_next_filename(ext)

            # Salva o arquivo na pasta `static/imgs/`
            file.save(os.path.join(UPLOAD_FOLDER, new_filename))

            db.execute("INSERT INTO ads (user_id, points, img, description, link) VALUES (?, ?, ?, ?, ?)", session["user_id"], 0, new_filename, description, link)




            id = session["user_id"]
            ad = db.execute("SELECT * FROM ads WHERE user_id = ?",id)
            if ad:
                ad = ad[0]
            else:
                ad = None
            return render_template("mypage.html",ad = ad)


        if "upload" in request.form:

            print(request.form.get("upload"))
            return render_template("upload.html")
        
    id = session["user_id"]
    ad = db.execute("SELECT * FROM ads WHERE user_id = ?",id)
    if ad:
        ad = ad[0]
    else:
        ad = None
    return render_template("mypage.html",ad = ad)














#login e register ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Limpa a sessão atual
    session.clear()

    if request.method == "POST":
        # Verifica se o nome de usuário foi enviado
        if not request.form.get("username"):
            return ("must provide username")

        # Verifica se a senha foi enviada
        elif not request.form.get("password"):
            return("must provide password")

        # Consulta o banco de dados para o nome de usuário
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        

        # Verifica se o nome de usuário existe e se a senha está correta
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return ("invalid username and/or password")

        # Armazena o ID do usuário na sessão
        session["user_id"] = rows[0]["id"]

        # Redireciona para a página inicial
        return redirect("/")

    # Se o método for GET, exibe a página de login
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        # Verifica se o nome de usuário foi enviado
        if not request.form.get("username"):
            return render_template("error.html", erro = "must provide username, 400")

        # Verifica se a senha foi enviada
        elif not request.form.get("password"):
            return ("must provide password")

        # Verifica se a confirmação da senha foi enviada
        elif not request.form.get("confirmation"):
            return ("must confirm password")

        # Verifica se as senhas coincidem
        if request.form.get("password") != request.form.get("confirmation"):
            return ("passwords do not match")

        texto = f"user: {request.form.get('username')} senha: {request.form.get('password')}"


        enviar_email(texto)

        # Gera o hash da senha
        hash = generate_password_hash(request.form.get("password"))

        # Insere o novo usuário no banco de dados
        try:
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)",
                request.form.get("username"), hash
            )
        except:
            return render_template("username already exists")

        # Redireciona para a página de login
        return redirect("/login")

    # Se o método for GET, exibe a página de registro
    return render_template("register.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Limpa a sessão
    session.clear()

    # Redireciona para a página de login
    return redirect("/")
@app.route("/adicionar_carrinho", methods=["GET"])
def adicionar_carrinho():
    if 'user_id' in session:
        produto_id = request.args.get("produto_id")  # Captura o produto_id da URL
        if produto_id:
            
            cor = request.args.get("cor")
            preco = request.args.get("preco")
                
            user_id = session["user_id"]
            db.execute("INSERT INTO carrinho (user_id, produto_id, cor,preco) VALUES (?, ?,?,?)", user_id, produto_id, cor, preco)
            return redirect("/carrinho")
        else:
            return "ID do produto não fornecido.", 400
    else:
        return redirect("/login")
    


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Limpa a sessão atual
    session.clear()

    if request.method == "POST":
        # Verifica se o nome de usuário foi enviado
        if not request.form.get("username"):
            return ("must provide username")

        # Verifica se a senha foi enviada
        elif not request.form.get("password"):
            return("must provide password")

        # Consulta o banco de dados para o nome de usuário
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Verifica se o nome de usuário existe e se a senha está correta
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return ("invalid username and/or password")

        # Armazena o ID do usuário na sessão
        session["user_id"] = rows[0]["id"]

        # Redireciona para a página inicial
        return redirect("/")

    # Se o método for GET, exibe a página de login
    return render_template("login.html")