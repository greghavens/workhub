FROM ghcr.io/astral-sh/uv:0.9.26 AS uv
FROM python:3.13-slim
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_LINK_MODE=copy PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev && useradd --create-home --uid 10001 workhub
USER workhub
EXPOSE 8000
CMD ["workhub", "serve", "--host", "0.0.0.0"]
