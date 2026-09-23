FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home site && mkdir /data && chown site:site /data
COPY app.py fields.json ./
COPY templates ./templates
COPY static ./static
USER site
EXPOSE 8000
CMD ["gunicorn","--bind","0.0.0.0:8000","--workers","2","--threads","2","--timeout","45","app:app"]
