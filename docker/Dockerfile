FROM python:3.12-slim

WORKDIR /app
COPY . .

CMD ["python", "dashboard/app.py", "--log", "data/sample-auth.log", "--threshold", "3", "--out-dir", "reports"]
