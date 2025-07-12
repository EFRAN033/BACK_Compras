import bcrypt

password = "admin".encode('utf-8')  # Contraseña en texto plano
hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
print(hashed_password)