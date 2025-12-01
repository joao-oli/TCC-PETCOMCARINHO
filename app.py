import os
import re
from datetime import datetime
from zoneinfo import ZoneInfo
from functools import wraps
import pytz
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session, abort
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, current_user, logout_user, login_required
)
from flask_migrate import Migrate
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, ValidationError

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///petshop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'producoespjomal@gmail.com'
app.config['MAIL_PASSWORD'] = 'nyesbssasxnsirzt'

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def gerar_token(email):
    return serializer.dumps(email, salt='recuperacao_senha')

def validar_token(token, expira_em=3600):
    try:
        email = serializer.loads(token, salt='recuperacao_senha', max_age=expira_em)
        return email
    except Exception:
        return None

def enviar_email_recuperacao(user):
    token = gerar_token(user.email)
    link = url_for('recadastrar', token=token, _external=True)
    msg = Message(
        subject="Recuperação de senha - Pet Com Carinho",
        sender=app.config['MAIL_USERNAME'],
        recipients=[user.email]
    )
    msg.body = (
        f"Olá, {user.username},\n\n"
        f"Para redefinir sua senha, clique no link abaixo:\n{link}\n\n"
        "Se você não solicitou, ignore este email."
    )
    mail.send(msg)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'



if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

migrate = Migrate(app, db)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

with app.app_context():
    db.create_all() 


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role != role:
                abort(403)  
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_password(form, field):
    password = field.data
    if len(password) < 6:
        raise ValidationError('A senha deve ter pelo menos 6 caracteres.')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('A senha deve conter pelo menos uma letra maiúscula.')
    if not re.search(r'\d', password):
        raise ValidationError('A senha deve conter pelo menos um número.')
    if not re.search(r'[!@#\$%\^&\*]', password):
        raise ValidationError('A senha deve conter pelo menos um caractere especial (!, @, #, $, etc.).')
    
class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                           validators=[DataRequired(message="O nome de usuário é obrigatório."), 
                                      Length(min=3, max=20, message="O nome de usuário deve ter entre 3 e 20 caracteres.")])
    
    email = StringField('Email', 
                        validators=[DataRequired(message="O email é obrigatório."), 
                                    Email(message="Digite um email válido.")])
    
    password = PasswordField('Password', 
                             validators=[DataRequired(message="A senha é obrigatória."),
                                        validate_password])
    
    confirm_password = PasswordField('Confirm Password', 
                                     validators=[DataRequired(message="A confirmação da senha é obrigatória."),
                                                EqualTo('password', message="As senhas devem ser iguais.")])
    
    role = SelectField('Role', 
                       choices=[('cliente', 'Cliente'), ('prestador', 'Prestador de Serviços')],
                       validators=[DataRequired(message="Escolha um papel.")])
    
    telefone = StringField('Telefone', 
                           validators=[Optional(), Length(min=10, max=15, message="O telefone deve ter entre 10 e 15 caracteres.")])

    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Este email já está em uso. Escolha outro.')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Este nome de usuário já está em uso. Escolha outro.')

@app.route('/graficos_financeiros')
@login_required
def graficos_financeiros():
    transacoes = Transacao.query.filter_by(cliente_id=current_user.cliente.id).all()
    transacoes_json = [
        {
            'tipo': t.tipo,
            'valor': t.valor,
            'descricao': t.descricao,
            'data': t.data.strftime('%Y-%m-%d')
        }
        for t in transacoes
    ]
    return render_template('graficos.html', transacoes=transacoes_json)

  
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))  
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user_email = User.query.filter_by(email=form.email.data).first()

        if user_email:
           
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
            cliente = Cliente.query.get(user_email.cliente_id)
            if cliente:
                cliente.nome = form.username.data
                cliente.email = form.email.data
                cliente.telefone = form.telefone.data
                db.session.commit() 
            
            user_email.username = form.username.data
            user_email.password = hashed_password 
            user_email.role = form.role.data  
            db.session.commit()  

            flash('Seu cadastro foi atualizado com sucesso! Agora você pode fazer login.', 'success')
            return redirect(url_for('login')) 
        
        else:
            
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
            cliente = Cliente(nome=form.username.data, email=form.email.data, telefone=form.telefone.data)
            db.session.add(cliente)
            db.session.commit()  

            user = User(username=form.username.data, email=form.email.data, password=hashed_password, 
                        role=form.role.data, cliente_id=cliente.id)
            db.session.add(user)
            db.session.commit()

            flash('Sua conta foi criada com sucesso! Agora você pode fazer login.', 'success')
            return redirect(url_for('login'))  
    
    return render_template('register.html', form=form)

@app.route('/recadastrar/<token>', methods=['GET', 'POST'])
def recadastrar(token):
    email = validar_token(token)
    if not email:
        flash("Token inválido ou expirado.", "danger")
        return redirect(url_for('esqueci_senha'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Usuário não encontrado.", "danger")
        return redirect(url_for('esqueci_senha'))

    if request.method == 'POST':
        nova_senha = request.form.get('password')
        confirmar = request.form.get('confirm_password')

        if not nova_senha or not confirmar:
            flash("Preencha todos os campos.", "danger")
            return render_template('recadastrar.html')

        if nova_senha != confirmar:
            flash("As senhas não coincidem.", "danger")
            return render_template('recadastrar.html')

        try:
            validate_password(None, type('obj', (object,), {'data': nova_senha}))
        except ValidationError as e:
            flash(str(e), "danger")
            return render_template('recadastrar.html')

        hashed = bcrypt.generate_password_hash(nova_senha).decode('utf-8')
        user.password = hashed
        db.session.commit()

        flash("Senha redefinida com sucesso! Faça login.", "success")
        return redirect(url_for('login'))

    return render_template('recadastrar.html')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'cliente':
            return redirect(url_for('home_cliente'))
        elif current_user.role == 'prestador':
            return redirect(url_for('home_prestador'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if bcrypt.check_password_hash(user.password, password):
                login_user(user)
                if user.role == 'cliente':
                    return redirect(url_for('home_cliente'))
                elif user.role == 'prestador':
                    return redirect(url_for('home_prestador'))
            else:
                flash('Senha incorreta. Por favor, tente novamente.', 'danger')  # Mensagem de senha incorreta
        else:
            flash('Email não encontrado. Por favor, tente novamente.', 'danger')
    
    return render_template('login.html')

@app.route("/home_cliente")
@login_required
@role_required('cliente')
def home_cliente():
    return render_template('homecliente.html')


@app.route('/meu_carrinho', methods=['GET', 'POST'])
@login_required
def meu_carrinho():
    cliente_id = current_user.cliente.id
    carrinho = Carrinho.query.filter_by(cliente_id=cliente_id, status='ativo').first()

    if request.method == 'POST':
        try:
            # Atualiza as quantidades conforme o input do usuário
            for item in carrinho.itens:
                quantidade_form = request.form.get(f'quantidade_{item.id}')
                if quantidade_form:
                    nova_quantidade = int(quantidade_form)
                    if nova_quantidade < 1:
                        nova_quantidade = 1  # Garantir que seja no mínimo 1
                    item.quantidade = nova_quantidade

            db.session.commit()  # Commit para salvar as quantidades atualizadas

            # Valida estoque
            for item in carrinho.itens:
                if item.produto.quantidade < item.quantidade:
                    flash(f"Estoque insuficiente para {item.produto.nome}.")
                    return redirect(url_for('meu_carrinho'))  # retorno obrigatório!

            # Dá baixa no estoque
            for item in carrinho.itens:
                item.produto.quantidade -= item.quantidade

            # Finaliza a compra
            carrinho.status = 'finalizada'
            db.session.commit()

            flash("Compra finalizada com sucesso!")
            return redirect(url_for('finalizada_compra'))  # retorno obrigatório!

        except Exception as e:
            db.session.rollback()
            flash("Erro ao finalizar a compra.")
            return redirect(url_for('meu_carrinho'))  # retorno obrigatório!

    # método GET
    if not carrinho or not carrinho.itens:
        flash("Seu carrinho está vazio.")
        return render_template('meu_carrinho.html', carrinho_itens=[])

    carrinho_itens = carrinho.itens
    total_geral = sum(item.produto.preco * item.quantidade for item in carrinho_itens)

    return render_template('meu_carrinho.html', carrinho_itens=carrinho_itens, total_geral=total_geral)

import json

@app.route('/home_prestador')
@login_required
def home_prestador():
    # Busca todas as transações no banco (exemplo)
    # Ajuste conforme seu modelo e necessidade
    transacoes = []
    try:
        # Supondo que você importe o modelo Transacao do seu app.py
        transacoes_db = Transacao.query.order_by(Transacao.data.asc()).all()

        for t in transacoes_db:
            transacoes.append({
                'id': t.id,
                'tipo': t.tipo,  # 'entrada' ou 'saida'
                'valor': t.valor,
                'descricao': t.descricao,
                'data': t.data.strftime('%Y-%m-%dT%H:%M:%S')  # ISO format para JS
            })
    except Exception as e:
        print(f"Erro ao buscar transações: {e}")

    transacoes_json = json.dumps(transacoes)

    return render_template('homeprestador.html', transacoes=transacoes_json)


@app.route("/logout")
def logout():
    logout_user()
    flash("Você saiu com sucesso.", "success")
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden_error(error):
    if current_user.is_authenticated:
        if current_user.role == 'cliente':
            return redirect(url_for('home_cliente'))
        else:
            return redirect(url_for('home_prestador'))
    return render_template('403.html'), 403

@app.route('/users')
def show_users():
    users = User.query.all()  
    return render_template('users.html', users=users)

@app.before_request
def create_tables():
    db.create_all()

@app.route('/pet/<int:pet_id>')
def pet(pet_id):
    pet = Pet.query.get_or_404(pet_id)
    return jsonify({'especie': pet.especie})

@app.route('/pets_por_cliente/<int:cliente_id>')
def pets_por_cliente(cliente_id):
    cliente = Cliente.query.get_or_404(cliente_id)
    pets = Pet.query.filter_by(cliente_id=cliente_id).all()
    pets_data = [{'id': pet.id, 'nome': pet.nome} for pet in pets]
    return jsonify({'pets': pets_data})

@app.route('/clientes')
@login_required
def clientes():
    if current_user.role != 'prestador':
        flash("Acesso negado! Apenas prestadores podem acessar esta página.")
        return redirect(url_for('home_cliente'))  
    
    usuarios_cliente = User.query.filter_by(role='cliente').all()  
    
    return render_template('clientes.html', usuarios_cliente=usuarios_cliente)

@app.route('/adicionar_cliente', methods=['GET', 'POST'])
def adicionar_cliente():
    if request.method == 'POST':
        nome = request.form['nome']
        telefone = request.form['telefone']
        email = request.form['email']

        cliente_existente = Cliente.query.filter_by(email=email).first()
        if cliente_existente:
            flash('Este email já está associado a um cliente.', 'danger')
            return redirect(url_for('adicionar_cliente'))  

        novo_cliente = Cliente(nome=nome, telefone=telefone, email=email)
        db.session.add(novo_cliente)
        db.session.commit()

        novo_usuario = User(username=email, email=email, role='cliente', cliente_id=novo_cliente.id, password='senha_segura')  
        db.session.add(novo_usuario)
        db.session.commit()

        flash('Cliente adicionado com sucesso!', 'success')
        return redirect(url_for('clientes'))  

    return render_template('adicionar_cliente.html') 

@app.route('/adicionar_pet/<int:cliente_id>', methods=['GET', 'POST'])
@login_required  
def adicionar_pet(cliente_id):
    cliente = Cliente.query.get_or_404(cliente_id)
    if request.method == 'POST':
        nome = request.form['nome']
        idade = request.form['idade']
        sexo = request.form['sexo']
        especie = request.form['especie']
        
        foto = None
        if 'foto' in request.files:
            file = request.files['foto']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                foto_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(foto_path)  
                foto = filename  

        novo_pet = Pet(nome=nome, idade=idade, sexo=sexo, especie=especie, cliente_id=cliente_id, foto=foto)
        db.session.add(novo_pet)
        db.session.commit()

        if current_user.is_authenticated and current_user.role == 'cliente':
            return redirect(url_for('meus_pets'))
        else:
            return redirect(url_for('ver_pets', cliente_id=cliente_id))
    
    return render_template('adicionar_pet.html', cliente=cliente)
        
@app.route('/editar_cliente/<int:id>', methods=['GET', 'POST'])
def editar_cliente(id):
    cliente = Cliente.query.get_or_404(id)
    
    agendamento = Agendamento.query.filter_by(cliente_id=id).first()

    if request.method == 'POST':
        cliente.nome = request.form['nome']
        cliente.telefone = request.form['telefone']
        cliente.email = request.form['email']
        db.session.commit()

        return redirect(url_for('clientes'))

    return render_template('editar_cliente.html', cliente=cliente, agendamento=agendamento)

@app.route('/remover_cliente/<int:id>', methods=['POST'])
def remover_cliente(id):
    cliente = Cliente.query.get_or_404(id)
    
    for pet in cliente.pets:
        for agendamento in pet.agendamentos:
            db.session.delete(agendamento)
        db.session.delete(pet)
    
    db.session.delete(cliente)
    db.session.commit()

    return redirect(url_for('clientes'))

@app.route('/pets')
@login_required
def pets():
    if current_user.role == 'cliente':
        flash("Acesso negado! Clientes não podem acessar esta página.")
        return redirect(url_for('home_cliente'))  
    
    pets = Pet.query.all()  
    cliente = Cliente.query.first()  

    return render_template('pets.html', pets=pets, cliente=cliente)

@app.route('/clientes/<int:cliente_id>/pets')
def ver_pets(cliente_id):
    cliente = Cliente.query.get_or_404(cliente_id)
    pets = Pet.query.filter_by(cliente_id=cliente_id).all()
    return render_template('ver_pets.html', cliente=cliente, pets=pets)

@app.route('/editar_pet/<int:id>', methods=['GET', 'POST'])
def editar_pet(id):
    pet = Pet.query.get_or_404(id)

    if request.method == 'POST':
        pet.nome = request.form['nome']
        pet.especie = request.form['especie']
        pet.cliente_id = request.form['cliente_id']
        
        if 'foto' in request.files:
            file = request.files['foto']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                foto_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(foto_path)  
                pet.foto = filename  

        db.session.commit()
        
        if current_user.role == 'cliente':
            return redirect(url_for('meus_pets'))  
        else:
            return redirect(url_for('pets'))  

    clientes = Cliente.query.all()
    return render_template('editar_pet.html', pet=pet, clientes=clientes)

@app.route('/remover_pet/<int:id>', methods=['POST'])
@login_required
def remover_pet(id):
    pet = Pet.query.get_or_404(id)
    db.session.delete(pet)
    db.session.commit()

    if current_user.role == 'cliente':
        return redirect(url_for('meus_pets'))
    else:
        return redirect(url_for('pets'))


@app.route('/adicionar_agendamento', methods=['GET', 'POST'])
@login_required
def adicionar_agendamento():
    if request.method == 'POST':
        cliente_id = request.form.get('cliente_id')
        pet_id = request.form.get('pet_id')
        especie = request.form.get('especie')  # <- este campo está disabled no HTML, não envia nada!
        servico = request.form.get('servico')
        data = request.form.get('data')
        horario = request.form.get('horario')

        # CORREÇÃO AQUI !!!
        prestador_id = request.form.get('prestador_id')

        produtos_ids = request.form.getlist('produtos')
        quantidades = [int(request.form[f'quantidade_{pid}']) for pid in produtos_ids]

        # AJUSTE 1: remover especie do obrigatório porque input disabled NÃO envia valor
        if not cliente_id or not pet_id or not servico or not data or not horario or not prestador_id:
            return "Todos os campos são obrigatórios.", 400

        cliente = Cliente.query.get(cliente_id)
        pet = Pet.query.get(pet_id)

        if not cliente or not pet:
            return "Cliente ou Pet não encontrados.", 404

        try:
            data_formatada = datetime.strptime(data, '%Y-%m-%d').date()
            horario_formatado = datetime.strptime(horario, '%H:%M').time()
        except ValueError:
            return "Formato de data ou horário inválido.", 400

        # AJUSTE 2: especie deve vir da tabela Pet
        especie_final = pet.especie

        agendamento = Agendamento(
            cliente_id=cliente_id,
            pet_id=pet_id,
            especie=especie_final,
            servico=servico,
            data=data_formatada,
            horario=horario_formatado,

            # AJUSTE 3: agora salvar o ID do prestador corretamente
            prestador=prestador_id
        )

        db.session.add(agendamento)
        db.session.commit()

        for i, produto_id in enumerate(produtos_ids):
            produto = Produto.query.get(produto_id)
            quantidade_usada = quantidades[i]
            
            if produto.quantidade < quantidade_usada:
                return f"Não há estoque suficiente para o produto {produto.nome}.", 400

            produto.quantidade -= quantidade_usada
            db.session.commit()

            agendamento_produto = AgendamentoProduto(
                agendamento_id=agendamento.id,
                produto_id=produto.id,
                quantidade=quantidade_usada
            )
            db.session.add(agendamento_produto)

        db.session.commit()

        if current_user.role == 'prestador':
            return redirect(url_for('agendamentos'))
        else:
            return redirect(url_for('meus_agendamentos'))

    clientes = Cliente.query.all()
    produtos = Produto.query.all()
    pets = Pet.query.all()

    if current_user.role == "cliente":
        pets = Pet.query.filter_by(cliente_id=current_user.id).all()
    else:
        pets = Pet.query.all()

    prestadores = User.query.filter_by(role='prestador').all()
    return render_template(
        'adicionar_agendamento.html',
        clientes=clientes,
        produtos=produtos,
        pets=pets,
        prestadores=prestadores
    )


@app.route('/agendamentos')
@login_required
def agendamentos():
    # Verifica se o usuário é um cliente
    if current_user.role == 'cliente':
        flash("Acesso negado! Clientes não podem acessar esta página.")
        return redirect(url_for('home_cliente'))  # Redireciona para a home do cliente
    
    # Caso o usuário seja prestador ou outro papel permitido
    agendamentos = Agendamento.query.all()  # Todos os agendamentos
    return render_template('agendamentos.html', agendamentos=agendamentos)


@app.route('/agendamentos/editar/<int:id>', methods=['GET', 'POST'])
def editar_agendamento(id):
    agendamento = Agendamento.query.get(id)
    
    if not agendamento:
        flash("Agendamento não encontrado.", "error")
        return redirect(url_for('agendamentos'))

    clientes = Cliente.query.all()
    pets = Pet.query.all()
    produtos = Produto.query.all()

    if request.method == 'POST':
        try:
            data_str = request.form.get('data', '').strip()
            if '-' in data_str:
                agendamento.data = datetime.strptime(data_str, '%Y-%m-%d').date()
            else:
                agendamento.data = datetime.strptime(data_str, '%d/%m/%Y').date()

            horario_str = request.form.get('horario', '').strip()
            agendamento.horario = datetime.strptime(horario_str, '%H:%M').time()

            agendamento.servico = request.form.get('servico', agendamento.servico)
            agendamento.prestador = request.form.get('prestador', agendamento.prestador)
            agendamento.cliente_id = request.form.get('cliente_id', agendamento.cliente_id)
            agendamento.pet_id = request.form.get('pet_id', agendamento.pet_id)

            produto_ids = request.form.getlist('produtos')  
            quantidade = int(request.form.get('quantidade', 1))  

            for agendamento_produto in agendamento.produtos:
                produto = Produto.query.get(agendamento_produto.produto_id)
                if produto:
                    produto.quantidade += agendamento_produto.quantidade  
            db.session.commit()  

            for produto_id in produto_ids:
                produto = Produto.query.get(int(produto_id))
                if produto:
                    if produto.quantidade < quantidade:
                        flash(f"Estoque insuficiente para o produto {produto.nome}.", "error")
                        return redirect(url_for('editar_agendamento', id=id))

            for produto_id in produto_ids:
                produto = Produto.query.get(int(produto_id))
                if produto:
                    produto.quantidade -= quantidade  
            db.session.commit()  

            agendamento.produtos = []  

            for produto_id in produto_ids:
                produto = Produto.query.get(int(produto_id))
                if produto:
                    agendamento_produto = AgendamentoProduto(agendamento_id=agendamento.id, produto_id=produto.id, quantidade=quantidade)
                    agendamento.produtos.append(agendamento_produto)

            db.session.commit()  
            flash("Agendamento atualizado com sucesso!", "success")
            return redirect(url_for('agendamentos'))

        except ValueError as e:
            flash(f"Erro na data ou horário: {e}", "error")

    return render_template('editar_agendamento.html', agendamento=agendamento, clientes=clientes, pets=pets, produtos=produtos)

@app.route('/remover_agendamento/<int:id>', methods=['GET', 'POST'])
def remover_agendamento(id):
    agendamento = Agendamento.query.get(id)
    if agendamento:
        for agendamento_produto in agendamento.produtos:
            produto = agendamento_produto.produto
            produto.quantidade += agendamento_produto.quantidade
            db.session.commit()  

            db.session.delete(agendamento_produto)

        db.session.delete(agendamento)
        db.session.commit()

        flash("Agendamento removido com sucesso e estoque atualizado!", "success")

        if current_user.role == 'cliente':  
            return redirect(url_for('meus_agendamentos'))
        else:  
            return redirect(url_for('agendamentos'))
    else:
        flash("Agendamento não encontrado.", "error")
        return redirect(url_for('agendamentos'))  

@app.route('/estoque')
@login_required
def estoque():
    if current_user.role == 'cliente':
        flash("Acesso negado! Clientes não podem acessar esta página.")
        return redirect(url_for('home_cliente')) 
    
    produtos = Produto.query.all()  
    return render_template('estoque.html', produtos=produtos)

@app.route('/adicionar_produto', methods=['GET', 'POST'])
@login_required
@role_required('prestador')  
def adicionar_produto():
    if request.method == 'POST':
        nome = request.form['nome']
        descricao = request.form['descricao']
        quantidade = request.form['quantidade']
        preco = request.form['preco']
        
        foto = request.files['foto']
        foto_filename = None
        
        if foto and allowed_file(foto.filename):  
            foto_filename = secure_filename(foto.filename)
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_filename))
        
        novo_produto = Produto(
            nome=nome,
            descricao=descricao,
            quantidade=quantidade,
            preco=preco,
            foto=foto_filename,
            prestador_id=current_user.id  
        )
        
        db.session.add(novo_produto)
        db.session.commit()
        
        flash('Produto adicionado com sucesso!', 'success')
        return redirect(url_for('estoque'))  
    
    return render_template('adicionar_produto.html')


@app.route('/editar_produto/<int:id>', methods=['GET', 'POST'])
def editar_produto(id):
    produto = Produto.query.get_or_404(id)
    if request.method == 'POST':
        produto.nome = request.form['nome']
        produto.descricao = request.form['descricao']
        produto.quantidade = request.form['quantidade']
        produto.preco = request.form['preco']
        db.session.commit()
        return redirect(url_for('estoque'))  
    return render_template('editar_produto.html', produto=produto)


@app.route('/remover_produto/<int:id>', methods=['POST'])
def remover_produto(id):
    produto = Produto.query.get_or_404(id)
    db.session.delete(produto)
    db.session.commit()
    return redirect(url_for('estoque'))

@app.route('/financeiro')
@login_required
def financeiro():
    if current_user.role == 'cliente':
        flash("Acesso negado! Clientes não podem acessar esta página.")
        return redirect(url_for('home_cliente'))  
    
    transacoes = Transacao.query.all()  
    return render_template('financeiro.html', transacoes=transacoes)

from datetime import datetime
import pytz

@app.route('/adicionar_transacao', methods=['GET', 'POST'])
def adicionar_transacao():
    clientes = Cliente.query.all()

    if request.method == 'POST':
        tipo = request.form.get('tipo')
        valor = request.form.get('valor')
        descricao = request.form.get('descricao')
        cliente_id = request.form.get('cliente_id')

        if not tipo or not valor or not cliente_id:
            return "Campos obrigatórios faltando", 400

        brasilia_time = datetime.now(pytz.timezone('America/Sao_Paulo'))

        try:
            nova_transacao = Transacao(
                tipo=tipo,
                valor=float(valor),
                descricao=descricao,
                cliente_id=int(cliente_id),
                data=brasilia_time  # define aqui a data com fuso horário correto
            )
            db.session.add(nova_transacao)
            db.session.commit()
            return redirect(url_for('financeiro'))
        except Exception as e:
            return f"Erro ao salvar a transação: {e}", 500

    return render_template('adicionar_transacao.html', clientes=clientes)


@app.route('/editar_transacao/<int:id>', methods=['GET', 'POST'])
def editar_transacao(id):
    transacao = Transacao.query.get(id)
    if not transacao:
        return "Transação não encontrada", 404

    if request.method == 'POST':
        transacao.tipo = request.form['tipo']
        transacao.valor = request.form['valor']
        transacao.descricao = request.form['descricao']
        
        db.session.commit()
        return redirect(url_for('financeiro'))
    
    return render_template('editar_transacao.html', transacao=transacao)

@app.route('/remover_transacao/<int:id>', methods=['POST'])
def remover_transacao(id):
    transacao = Transacao.query.get(id)
    if transacao:
        db.session.delete(transacao)
        db.session.commit()
    return redirect(url_for('financeiro'))  

@app.route('/editar_perfil', methods=['GET', 'POST'])
@login_required
@role_required('cliente')
def editar_perfil():
    if request.method == 'POST':
        current_user.nome = request.form['nome']
        current_user.email = request.form['email']
        db.session.commit()
        flash('Perfil atualizado com sucesso!')
        return redirect(url_for('editar_perfil'))
    
    return render_template('editar_perfil.html')

@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
def editar_usuario(id):
    pass


@app.route('/meus_pets')
@login_required
@role_required('cliente')
def meus_pets():
    pets = Pet.query.filter_by(cliente_id=current_user.id).all()
    return render_template('meus_pets.html', cliente=current_user, pets=pets)



@app.route('/meus_agendamentos')
@login_required
@role_required('cliente')
def meus_agendamentos():
    agendamentos = Agendamento.query.filter_by(cliente_id=current_user.id).all()
    return render_template('meus_agendamentos.html', agendamentos=agendamentos)

@app.route('/loja')
@login_required
@role_required('cliente')
def loja():
    produtos = Produto.query.all()  
    return render_template('loja.html', produtos=produtos)

@app.route('/graficos')
def graficos():
    return render_template('graficos.html')



@app.route('/adicionar_ao_carrinho/<int:produto_id>')
@login_required
def adicionar_ao_carrinho(produto_id):
    # Pega o cliente_id correto da relação usuário->cliente
    cliente_id = current_user.cliente.id

    # Buscar carrinho existente ou criar um novo
    carrinho = Carrinho.query.filter_by(cliente_id=cliente_id, status='ativo').first()
    if not carrinho:
        carrinho = Carrinho(cliente_id=cliente_id, status='ativo')
        db.session.add(carrinho)
        db.session.commit()  # Gera o carrinho.id

    # Buscar o produto
    produto = Produto.query.get(produto_id)
    if not produto:
        flash("Produto não encontrado.")
        return redirect(url_for('loja'))  # Ou outra página

    # Verificar se o produto já está no carrinho para esse carrinho
    item = CarrinhoItem.query.filter_by(carrinho_id=carrinho.id, produto_id=produto_id).first()
    if item:
        # Incrementa a quantidade
        item.quantidade += 1
    else:
        # Cria novo item
        item = CarrinhoItem(
            carrinho_id=carrinho.id,
            produto_id=produto.id,
            cliente_id=cliente_id,
            quantidade=1
        )
        db.session.add(item)

    db.session.commit()
    flash(f"Produto {produto.nome} adicionado ao carrinho.")
    return redirect(url_for('meu_carrinho'))

@app.route('/atualizar_carrinho', methods=['POST'])
@login_required
def atualizar_carrinho():
    carrinho = Carrinho.query.filter_by(cliente_id=current_user.id, status='pendente').first()

    if not carrinho:
        flash('Carrinho não encontrado.', 'danger')
        return redirect(url_for('loja'))

    for item in carrinho.itens:
        nova_quantidade = request.form.get(f'quantidade_{item.id}')
        if nova_quantidade:
            try:
                nova_qtd = int(nova_quantidade)
                if nova_qtd > 0:
                    item.quantidade = nova_qtd
                else:
                    db.session.delete(item)
            except ValueError:
                # Ignora valores inválidos
                continue

    db.session.commit()
    flash('Carrinho atualizado com sucesso.', 'success')
    return redirect(url_for('meu_carrinho'))

@app.route('/remover_item/<int:item_id>')
@login_required
def remover_item(item_id):
    item = CarrinhoItem.query.get(item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for('meu_carrinho'))

@app.route('/remover_usuario/<int:id>')
def remover_usuario(id):
    return f"Usuário com ID {id} removido com sucesso!"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/perfil_cliente')
@login_required
def perfil_cliente():
    return render_template('perfil_cliente.html')


@app.route('/finalizada_compra')
@login_required
def finalizada_compra():
    cliente_id = current_user.cliente.id

    carrinho = Carrinho.query.filter_by(cliente_id=cliente_id, status='finalizada').order_by(Carrinho.id.desc()).first()

    if not carrinho or not carrinho.itens:
        flash("Nenhum item encontrado.")
        return render_template('finalizada_compra.html', itens=[])

    itens = carrinho.itens
    total = sum(item.produto.preco * item.quantidade for item in itens)

    transacao_existente = Transacao.query.filter_by(
        cliente_id=cliente_id,
        valor=total,
        descricao=f'Compra finalizada - carrinho #{carrinho.id}'
    ).first()

    if not transacao_existente:
        brasilia_time = datetime.now(pytz.timezone('America/Sao_Paulo'))  # pega o horário de Brasília
        nova_transacao = Transacao(
            tipo='entrada',
            valor=total,
            descricao=f'Compra finalizada - carrinho #{carrinho.id}',
            cliente_id=cliente_id,
            data=brasilia_time  # define a data aqui
        )
        db.session.add(nova_transacao)
        db.session.commit()

    return render_template('finalizada_compra.html', itens=itens, total=total)

@app.route('/confirmar_compra', methods=['POST'])
@login_required
def confirmar_compra():
    return redirect(url_for('home'))

@app.route("/esqueci_senha", methods=['GET', 'POST'])
def esqueci_senha():
    if request.method == 'POST':
        email = request.form.get('email')
        nome = request.form.get('nome')

        user = User.query.filter_by(email=email, username=nome).first()

        if user:
            try:
                enviar_email_recuperacao(user)
                flash("Um link de recuperação de senha foi enviado para seu email.", "success")
            except Exception as e:
                flash(f"Erro ao enviar email: {e}", "danger")
        else:
            flash("Usuário não encontrado. Verifique o nome e o email.", "danger")

    return render_template("esqueci_senha.html")


class Produto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    descricao = db.Column(db.String(255))
    quantidade = db.Column(db.Integer, nullable=False)
    preco = db.Column(db.Float, nullable=False)
    foto = db.Column(db.String(120))  
    imagem = db.Column(db.String(200), nullable=True)  
    prestador_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
    prestador = db.relationship('User', backref=db.backref('produtos', lazy=True))

    def __repr__(self):
        return f'<Produto {self.nome}>'

class Cliente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    telefone = db.Column(db.String(20), nullable=True)  

    financeiros = db.relationship('LancamentoFinanceiro', back_populates='cliente', lazy=True)

    pets = db.relationship('Pet', back_populates='cliente', lazy=True)

    usuario = db.relationship('User', back_populates='cliente', uselist=False)

    def __repr__(self):
        return f'<Cliente {self.nome}>'

class Pet(db.Model):
    __tablename__ = 'pet'

    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), nullable=False)
    idade = db.Column(db.Integer)
    sexo = db.Column(db.String(10))
    especie = db.Column(db.String(50))
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)  
    foto = db.Column(db.String(120), nullable=True)

    cliente = db.relationship('Cliente', back_populates='pets')

    def __repr__(self):
        return f'<Pet {self.nome}>'

class Agendamento(db.Model):
    __tablename__ = 'agendamentos'
    
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'))
    pet_id = db.Column(db.Integer, db.ForeignKey('pet.id'))
    especie = db.Column(db.String(50))
    servico = db.Column(db.String(50))
    data = db.Column(db.Date)
    horario = db.Column(db.Time)
    prestador = db.Column(db.String(100))

    cliente = db.relationship('Cliente', backref='agendamentos')
    pet = db.relationship('Pet', backref='agendamentos')
    
    produtos = db.relationship('AgendamentoProduto', back_populates='agendamento', cascade="all, delete-orphan")

    def __init__(self, cliente_id, pet_id, especie, servico, data, horario, prestador):
        self.cliente_id = cliente_id
        self.pet_id = pet_id
        self.especie = especie
        self.servico = servico
        self.data = data
        self.horario = horario
        self.prestador = prestador

class AgendamentoProduto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agendamento_id = db.Column(db.Integer, db.ForeignKey('agendamentos.id'), nullable=False)
    produto_id = db.Column(db.Integer, db.ForeignKey('produto.id'), nullable=False)
    quantidade = db.Column(db.Integer, nullable=False)

    agendamento = db.relationship('Agendamento', back_populates='produtos')
    produto = db.relationship('Produto')

    def __repr__(self):
        return f'<AgendamentoProduto {self.id}>'
    
class Transacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(50), nullable=False)  
    valor = db.Column(db.Float, nullable=False)
    descricao = db.Column(db.String(250))
    data = db.Column(db.DateTime, default=datetime.utcnow)
    
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)
    
    def __repr__(self):
        return f'<Transacao {self.tipo} {self.valor}>'


class LancamentoFinanceiro(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)
    tipo = db.Column(db.String(50), nullable=False)  
    valor = db.Column(db.Float, nullable=False)
    descricao = db.Column(db.String(255))

    cliente = db.relationship('Cliente', back_populates='financeiros')

    def __repr__(self):
        return f'<LancamentoFinanceiro {self.descricao}>'
    

class CarrinhoItem(db.Model):
    __tablename__ = 'carrinho_item'
    __table_args__ = (db.UniqueConstraint('carrinho_id', 'produto_id', name='_carrinho_produto_uc'),)
    
    id = db.Column(db.Integer, primary_key=True)
    carrinho_id = db.Column(db.Integer, db.ForeignKey('carrinho.id'))
    produto_id = db.Column(db.Integer, db.ForeignKey('produto.id'))
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)
    quantidade = db.Column(db.Integer, nullable=False)

    carrinho = db.relationship('Carrinho', back_populates='itens')
    produto = db.relationship('Produto')
    cliente = db.relationship('Cliente')

class Carrinho(db.Model):
    __tablename__ = 'carrinho'
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'))
    status = db.Column(db.String, nullable=False)

    itens = db.relationship('CarrinhoItem', back_populates='carrinho')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='cliente')
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'))  
    cliente = db.relationship('Cliente', back_populates='usuario', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}')"

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  
    app.run(host='0.0.0.0', port=5000)