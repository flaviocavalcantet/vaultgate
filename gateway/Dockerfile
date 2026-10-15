FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN useradd --uid 10001 --no-create-home app
USER 10001

EXPOSE 8888 9100
CMD ["python", "-m", "vaultgate_gateway.app"]
