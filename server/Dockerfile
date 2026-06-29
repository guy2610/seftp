FROM python:3.11-slim

WORKDIR /app/server

COPY server/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY server/ ./

EXPOSE 1256

CMD ["python3", "server_async.py"]
