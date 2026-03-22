FROM python:3.12-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    curl \
    gnupg2 \
    unixodbc-dev \
    clamav \
    clamav-daemon \
    && rm -rf /var/lib/apt/lists/*

# Update ClamAV virus definitions
RUN freshclam || true

# Install Gitleaks
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks

# Install ODBC Driver 18 for SQL Server
RUN curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y msodbcsql18 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies + Semgrep
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt semgrep

# Copy application code
COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
