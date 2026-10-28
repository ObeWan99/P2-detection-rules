# Инструменты практики 2: переводчик Sigma -> Kibana и оценка правил
FROM python:3.12-slim
RUN pip install --no-cache-dir sigma-cli==3.1.0 pySigma==1.5.1 pySigma-backend-elasticsearch==2.1.1
COPY p2.py ground_truth.csv /app/
WORKDIR /rules
ENTRYPOINT ["python3", "/app/p2.py"]
