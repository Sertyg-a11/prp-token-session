FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# Run without TLS for the INSECURE profile; add --cert/--key for SECURE
CMD ["python", "run.py"]
