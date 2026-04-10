FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir flask requests flask-wtf psycopg2-binary

COPY app.py .
COPY templates/ templates/

ENV EDR_BACKEND=http://edr-backend:8080
ENV FLASK_ENV=production

EXPOSE 5000

CMD ["python", "app.py"]
