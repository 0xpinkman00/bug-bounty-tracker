FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && apt-get update && apt-get install -y --no-install-recommends libnotify-bin && rm -rf /var/lib/apt/lists/*
COPY backend ./backend
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
