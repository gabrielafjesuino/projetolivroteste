from flask import Flask, jsonify, request
from main import app, con
import re
from flask_bcrypt import generate_password_hash, check_password_hash

@app.route('/livro', methods=['GET'])
def livro():
    cur = con.cursor()
    cur.execute("SELECT id_livro, titulo, autor, ano_publicacao FROM livros")
    livros = cur.fetchall()
    livros_dic = []
    for livro in livros:
        livros_dic.append({
            'id_livro': livro[0],
            'titulo': livro[1],
            'autor': livro[2],
            'ano_publicacao': livro[3]
        })
    return jsonify(mensagem='Lista de Livros', livros=livros_dic)

@app.route('/livro', methods=['POST'])
def livro_post():
    data = request.get_json()
    titulo = data.get('titulo')
    autor = data.get('autor')
    ano_publicacao = data.get('ano_publicacao')

    cursor = con.cursor()

    cursor.execute("SELECT 1 FROM LIVROS WHERE TITULO = ?", (titulo,))

    if cursor.fetchone():
        return jsonify('Livro já cadastrado!')

    cursor.execute('INSERT INTO LIVROS (TITULO, AUTOR, ANO_PUBLICACAO) VALUES (?,?,?)', (titulo, autor, ano_publicacao))

    con.commit()
    cursor.close()

    return jsonify({
        'message':'Livro cadastrado com sucesso!',
        'livro': {
            'titulo': titulo,
            'autor': autor,
            'ano_publicacao': ano_publicacao
        }
    })

@app.route('/livro/<int:id>', methods=['PUT'])
def livro_put(id):
    cursor = con.cursor()
    cursor.execute("select id_livro, titulo, autor, ano_publicacao from livros WHERE id_livro = ?", (id,))
    livro_data = cursor.fetchone()

    if not livro_data:
        cursor.close()
        return jsonify({"error":"Livro não foi encontrado!"}),404

    data = request.get_json()
    titulo = data.get('titulo')
    autor = data.get('autor')
    ano_publicacao = data.get('ano_publicacao')

    cursor.execute("update livros set titulo = ?, autor = ?, ano_publicacao = ? where id_livro = ?",
                   (titulo, autor, ano_publicacao, id))

    con.commit()
    cursor.close()

    return jsonify({
        'message':'Livro atualizado com sucesso!',
        'livro': {
            'titulo': titulo,
            'autor': autor,
            'ano_publicacao': ano_publicacao
        }
    })

@app.route('/livros/<int:id>', methods=['DELETE'])
def deletar_livro(id):
    cursor = con.cursor()

    cursor.execute("SELECT 1 FROM livros WHERE ID_LIVRO = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Livro não encontrado"}), 404

    cursor.execute("DELETE FROM livros WHERE ID_LIVRO = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Livro excluído com sucesso!",
        'id_livro': id
    })

def validar_senha(senha):
    if (len(senha) >= 8 and
        re.search(r"[A-Z]", senha) and
        re.search(r"[a-z]", senha) and
        re.search(r"[0-9]", senha) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", senha)):
        return True
    return False

@app.route('/usuario', methods=['GET'])
def usuario():
    cur = con.cursor()
    cur.execute("SELECT id_usuario, nome, email, senha FROM usuarios")
    usuarios = cur.fetchall()
    usuarios_dic = []
    for usuario in usuarios:
        usuarios_dic.append({
            'id_usuario': usuario[0],
            'nome': usuario[1],
            'email': usuario[2],
            'senha': usuario[3]
        })
    return jsonify(mensagem='Lista de Usuários', usuarios=usuarios_dic)

@app.route('/usuario', methods=['POST'])
def usuario_post():
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')

    erro_senha = validar_senha(senha)
    if not erro_senha:
        return jsonify({"error:": "Senha inválida , deve ter pelo menos 1 letra maiúscula, 1 letra minúscula, 8 caracteres, 1 número e 1 caractere especial."}), 400

    cursor = con.cursor()

    cursor.execute("SELECT 1 FROM USUARIOS WHERE email = ?", (email,))

    if cursor.fetchone():
        return jsonify({'Usuário já cadastrado!'})

    senha = generate_password_hash(senha).decode('utf-8')

    cursor.execute('INSERT INTO USUARIOS (NOME, EMAIL, SENHA) VALUES (?,?,?)', (nome, senha, senha))

    con.commit()
    cursor.close()

    return jsonify({
        'message':'Usuário cadastrado com sucesso!',
        'usuario': {
            'nome': nome,
            'email': email,
            'senha': senha
        }
    })

@app.route('/usuario/<int:id>', methods=['PUT'])
def usuario_put(id):
    cursor = con.cursor()
    cursor.execute("select id_usuario, nome, email, senha from usuarios WHERE id_usuario = ?", (id,))
    usuario_data = cursor.fetchone()

    if not usuario_data:
        cursor.close()
        return jsonify({"error":"Usuário não foi encontrado!"}),404

    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')

    cursor.execute("update usuarios set nome = ?, email = ?, senha = ? where id_usuario = ?",
                   (nome, email, senha, id))

    con.commit()
    cursor.close()

    return jsonify({
        'message':'Usuário atualizado com sucesso!',
        'usuario': {
            'nome': nome,
            'email': email,
            'senha': senha
        }
    })

@app.route('/usuarios/<int:id>', methods=['DELETE'])
def deletar_usuario(id):
    cursor = con.cursor()

    cursor.execute("SELECT 1 FROM usuarios WHERE ID_USUARIO = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Usuário não encontrado"}), 404

    cursor.execute("DELETE FROM usuarios WHERE ID_USUARIO = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Usuário excluído com sucesso!",
        'id_usuario': id
    })

@app.route('/login', methods=['GET, POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')

    cursor = con.cursor()

    cursor.execute("SELECT senha FROM usuarios WHERE email = ?", (email, ))
    senha = cursor.fetchone()
    cursor.close()

    if not senha:
        return jsonify({"error: Usuário não encontrado!"}), 404

    senha_hash = senha[0]

    if check_password_hash(senha_hash, senha):
        return jsonify({'message': "Login realizado com sucesso!"}), 200

    return jsonify({"error": "E-mail ou senha inválidos!"}), 401