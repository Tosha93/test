import secrets
import string
import argparse

def generate_secure_password(length=16, min_lower=1, min_upper=1, min_digits=1, min_special=1):
    """
    Генерирует надежный пароль с заданной длиной и минимальным количеством символов каждого типа.

    :param length: Общая длина пароля (минимум 4).
    :param min_lower: Минимальное количество строчных букв.
    :param min_upper: Минимальное количество заглавных букв.
    :param min_digits: Минимальное количество цифр.
    :param min_special: Минимальное количество специальных символов.
    :return: Сгенерированный пароль.
    :raises ValueError: Если длина слишком маленькая или параметры некорректны.
    """
    if length < 4:
        raise ValueError("Длина пароля должна быть не менее 4 символов.")
    if min_lower + min_upper + min_digits + min_special > length:
        raise ValueError("Сумма минимальных количеств символов превышает общую длину.")

    # Наборы символов
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    special = string.punctuation

    # Гарантируем минимальное количество каждого типа
    password = (
        ''.join(secrets.choice(lower) for _ in range(min_lower)) +
        ''.join(secrets.choice(upper) for _ in range(min_upper)) +
        ''.join(secrets.choice(digits) for _ in range(min_digits)) +
        ''.join(secrets.choice(special) for _ in range(min_special))
    )

    # Дополняем до нужной длины случайными символами из полного алфавита
    all_chars = lower + upper + digits + special
    password += ''.join(secrets.choice(all_chars) for _ in range(length - len(password)))

    # Перемешиваем пароль для случайности
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    return ''.join(password_list)

def generate_token_password(length_bytes=16):
    """
    Генерирует URL-безопасный пароль с помощью secrets.token_urlsafe.

    :param length_bytes: Длина в байтах (строка будет длиннее из-за кодирования).
    :return: Сгенерированный пароль.
    """
    return secrets.token_urlsafe(length_bytes)

def main():
    parser = argparse.ArgumentParser(description="Генератор надежных паролей.")
    parser.add_argument('--length', type=int, default=16, help="Длина пароля (по умолчанию 16).")
    parser.add_argument('--type', choices=['secure', 'token', 'both'], default='both', help="Тип пароля: 'secure', 'token' или 'both' (по умолчанию 'both').")
    args = parser.parse_args()
    
    if args.type == 'secure' or args.type == 'both':
        password = generate_secure_password(args.length)
        print(f"Твой новый надежный пароль ({args.length} символов): {password}")
    
    if args.type == 'token' or args.type == 'both':
        password = generate_token_password(args.length)
        print(f"Пароль с token_urlsafe ({len(password)} символов): {password}")

if __name__ == "__main__":
    main()