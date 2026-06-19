FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:0.10.11 /uv /uvx /usr/local/bin/

WORKDIR /sing-box-subscribe

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY . .

EXPOSE 5000
CMD ["uv", "run", "python", "api/app.py"]
