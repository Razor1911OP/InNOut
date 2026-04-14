FROM python:3.12-slim

WORKDIR /app
ENV PYTHONPATH=/app/backend
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY backend /app/backend
COPY ml /app/ml

EXPOSE 8080
CMD ["uvicorn", "narip.main:app", "--host", "0.0.0.0", "--port", "8080"]
