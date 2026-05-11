FROM python:3.10-slim

WORKDIR /app

COPY sauron_brain.py .

RUN pip install fastapi uvicorn
RUN pip install sqlalchemy psycopg2-binary

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "sauron_brain:app", "--host", "0.0.0.0", "--port", "8000","--no-access-log", "--log-level", "warning"]