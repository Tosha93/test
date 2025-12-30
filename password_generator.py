import secrets
import string

def generate_secure_password(length=16):
    # Определяем набор символов
    alphabet = string.ascii_letters + string.digits + string.punctuation
    
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        # Проверка условий надежности
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_spec  = any(c in string.punctuation for c in password)
        
        if has_lower and has_upper and has_digit and has_spec:
            return password

def generate_token_password(length=16):
    # Генерируем пароль с помощью secrets.token_urlsafe (URL-безопасные символы: буквы, цифры, -, _)
    # Длина в байтах, строка будет длиннее из-за base64
    password = secrets.token_urlsafe(length)
    return password

print("Твой новый надежный пароль:")
print(generate_secure_password(20))

print("Пароль с token_urlsafe:")
print(generate_token_password(20))