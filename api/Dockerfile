FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
COPY alembic.ini ./
COPY migrations ./migrations
RUN pip install --no-cache-dir .

RUN useradd --uid 10001 --no-create-home app
USER 10001

EXPOSE 8000
# Apply pending migrations, then serve. Migrations hold a Postgres advisory lock, so
# replicas starting at the same time run them one after another.
CMD ["sh", "-c", "alembic upgrade head && exec python -m vaultgate_api"]
