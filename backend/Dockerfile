FROM python:3.11-slim

WORKDIR /app

# Install OS deps for bcrypt / lxml
RUN apt-get update && apt-get install -y --no-install-recommends gcc libffi-dev && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p instance reports/generated

EXPOSE 5000

ENV FLASK_APP=app.py
ENV FLASK_DEBUG=0

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--timeout", "120", "app:create_app()"]
