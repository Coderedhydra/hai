FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

# Copy backend source
COPY app /app/app

# Evidence and reports directories
RUN mkdir -p /evidence /reports
VOLUME ["/evidence", "/reports"]

EXPOSE 8000 5001

# Note: Playwright browsers are not installed by default to keep the image small.
# To enable the crawler with browsers in dev, you can extend this image and run:
#   RUN pip install playwright && python -m playwright install --with-deps chromium

