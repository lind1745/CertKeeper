# Используем официальный образ Python
FROM python:3.10-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файл с зависимостями
COPY requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь проект
COPY . .

# Создаем папку для данных
RUN mkdir -p /app/utm_cert_data

# Указываем порт, который будет слушать приложение
EXPOSE 5000

# Команда для запуска
CMD ["python", "utm_cert_server.py"]