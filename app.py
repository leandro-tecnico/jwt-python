from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

# Chave secreta para assinar os tokens (em produção, use uma chave complexa e segura)
app.config['SECRET_KEY'] = 'sua-chave-secreta-super-segura'

# Dados de usuário simulados (em um sistema real, isso viria de um banco de dados)
users = {
    'usuario1': {'password': 'senha123', 'role': 'admin'},
    'usuario2': {'password': 'senha456', 'role': 'user'}
}

# Decorator para verificar o token JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Verificar se o token foi enviado no cabeçalho Authorization
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token está faltando!'}), 401
        
        try:
            # Decodificar o token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Rota de login
@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Credenciais inválidas'}), 401
    
    username = auth['username']
    password = auth['password']
    
    # Verificar se o usuário existe e a senha está correta
    if username not in users or users[username]['password'] != password:
        return jsonify({'message': 'Usuário ou senha incorretos'}), 401
    
    # Criar o token JWT
    token = jwt.encode({
        'username': username,
        'role': users[username]['role'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }, app.config['SECRET_KEY'])
    
    return jsonify({'token': token})

# Rota protegida que requer autenticação
@app.route('/protegido', methods=['GET'])
@token_required
def protegido(current_user):
    return jsonify({
        'message': f'Bem-vindo, {current_user}!',
        'user_details': {
            'username': current_user,
            'role': users[current_user]['role']
        }
    })

if __name__ == '__main__':
    app.run(debug=True)