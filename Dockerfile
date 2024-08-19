FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
VOLUME /app/config
CMD ["python", "ip_monitor_modified_noprint_onthescreen.py"]
