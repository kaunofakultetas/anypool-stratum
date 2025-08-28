FROM python:3.13.1-alpine

# Set terminal width for better display in Docker logs
ENV COLUMNS=120
ENV LINES=50

WORKDIR /app

RUN pip install --no-cache-dir \
    "aiohttp==3.12.15"      \
    "scrypt==0.9.4"         \
    "pyboxen==1.3.0"

COPY . .

CMD ["python", "-u", "main.py"]