# syntax=docker/dockerfile:1
FROM python:3.11-slim

WORKDIR /app

# Copy project files
COPY pyproject.toml README.md /app/
COPY src /app/src
COPY templates /app/templates

# Install the package
RUN pip install --no-cache-dir -U pip && pip install --no-cache-dir .

# Install Chromium for Playwright inside the image
RUN python -m playwright install --with-deps chromium

# Default output folder
RUN mkdir -p /app/reports

ENTRYPOINT ["websentry"]
