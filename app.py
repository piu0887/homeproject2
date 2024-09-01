import sqlite3
import jwt
import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flasgger import Swagger

app = Flask(__name__)
app.secret_key = 'ghkdtkdvlf'  # JWT 발행 시 사용할 비밀 키

swagger = Swagger(app)


# 데이터베이스 연결 함수
def get_db_connection():
    """
    데이터베이스 연결을 생성하고 반환합니다.
    ---
    responses:
      200:
        description: 데이터베이스 연결 성공
    """
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# JWT 토큰 생성 함수
def create_token(sign_id, user_name):
    """
    JWT 토큰을 생성합니다.
    ---
    parameters:
      - name: sign_id
        in: query
        type: string
        required: true
        description: User's unique ID
      - name: user_name
        in: query
        type: string
        required: true
        description: User's name
    responses:
      200:
        description: JWT 토큰 생성 성공
    """
    payload = {
        'sign_id': sign_id,
        'user_name': user_name,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # 토큰 만료 시간 1시간
    }
    token = jwt.encode(payload, app.secret_key, algorithm='HS256')
    return token

# JWT 토큰 검증 함수
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        """
        JWT 토큰을 검증합니다.
        ---
        responses:
          403:
            description: JWT 토큰이 없거나 유효하지 않음
        """
        token = request.cookies.get('token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 403
        return f(data['sign_id'], data['user_name'], *args, **kwargs)
    return decorated

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    사용자 등록을 처리합니다.
    ---
    parameters:
      - name: sign_id
        in: formData
        type: string
        required: true
        description: User's unique ID
      - name: name
        in: formData
        type: string
        required: true
        description: User's name
      - name: email
        in: formData
        type: string
        required: true
        description: User's email
      - name: phone
        in: formData
        type: string
        required: false
        description: User's phone number
      - name: address
        in: formData
        type: string
        required: false
        description: User's address
      - name: type
        in: formData
        type: string
        required: false
        description: User's type (personal or company)
      - name: password
        in: formData
        type: string
        required: true
        description: User's password
      - name: confirm_password
        in: formData
        type: string
        required: true
        description: Confirmation of user's password
    responses:
      200:
        description: 사용자 등록 성공
      400:
        description: 비밀번호가 일치하지 않음
      409:
        description: Sign_ID 또는 Email 중복
      500:
        description: 서버 내부 오류. 사용자 등록 중 문제가 발생함
    """
    if request.method == 'POST':
        sign_id = request.form['sign_id']
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        user_type = request.form['type']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # 비밀번호 일치 여부 확인
        if password != confirm_password:
            return 'Passwords do not match! Please try again.', 400
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO users (Sign_ID, Name, Email, Phone, Address, Type, Password)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (sign_id, name, email, phone, address, user_type, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError as e:
            conn.close()
            if 'UNIQUE constraint failed: users.Sign_ID' in str(e):
                return 'User ID already exists!', 409
            if 'UNIQUE constraint failed: users.Email' in str(e):
                return 'Email already exists!', 409
            return 'An error occurred while signing up. Please try again.', 500
        conn.close()
        
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

# POST 요청에 대한 로그인 처리
@app.route('/login', methods=['POST'])
def login():
    """
    사용자가 로그인할 수 있도록 합니다.
    ---
    parameters:
      - name: sign_id
        in: formData  # POST 요청에서 사용됩니다.
        type: string
        required: true
        description: User's unique ID
      - name: password
        in: formData  # POST 요청에서 사용됩니다.
        type: string
        required: true
        description: User's password
    responses:
      200:
        description: 로그인 성공
      401:
        description: 로그인 실패 (잘못된 자격 증명)
    """
    sign_id = request.form['sign_id']
    password = request.form['password']

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE Sign_ID = ?', (sign_id,)).fetchone()
    conn.close()

    if user is None or not check_password_hash(user['Password'], password):
        return 'Invalid credentials!'

    token = create_token(user['Sign_ID'], user['Name'])
    response = make_response(redirect(url_for('dashboard')))
    response.set_cookie('token', token)
    return response

@app.route('/dashboard')
@token_required
def dashboard(sign_id, user_name):
    """
    대시보드를 렌더링합니다.
    ---
    responses:
      200:
        description: 대시보드 렌더링 성공
      403:
        description: 유효하지 않은 토큰
    """
    return render_template('dashboard.html', user_name=user_name)

@app.route('/myprofile')
@token_required
def myprofile(sign_id, user_name):
    """
    사용자의 프로필 정보를 보여줍니다.
    ---
    responses:
      200:
        description: 프로필 정보 반환 성공
      403:
        description: 유효하지 않은 토큰
    """
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE Sign_ID = ?', (sign_id,)).fetchone()
    conn.close()

    if user is None:
        return 'User not found!'
    
    return render_template('myprofile.html', user=user)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/logout')
def logout():
    """
    사용자가 로그아웃하도록 합니다.
    ---
    responses:
      200:
        description: 로그아웃 성공
    """
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('token')  # 쿠키에서 토큰 삭제
    return response

if __name__ == '__main__':
    app.run(debug=True)
