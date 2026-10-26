# AgentCore Runtime requires linux/arm64.
FROM --platform=linux/arm64 public.ecr.aws/docker/library/python:3.12-slim
RUN pip install --no-cache-dir "boto3>=1.40.0"
WORKDIR /app
COPY agent.py .
USER 1000
EXPOSE 8080
CMD ["python", "agent.py"]
