.PHONY: setup infra db-setup backend frontend worker dev test-backend test-frontend lint clean

# ─── Setup ────────────────────────────────
setup:
	cp -n .env.example .env || true
	cd backend && python -m venv venv && . venv/bin/activate && pip install -r requirements.txt
	cd frontend && npm install

# ─── Infrastructure ──────────────────────
ifneq (,$(wildcard .env))
  include .env
  export
endif

infra:
ifeq ($(USE_LOCAL_INFRA),false)
	@echo "Skipping infra (USE_LOCAL_INFRA=false)"
else
	docker compose -f docker/docker-compose.yml up -d
endif

infra-down:
ifeq ($(USE_LOCAL_INFRA),false)
	@echo "Skipping infra-down (USE_LOCAL_INFRA=false)"
else
	docker compose -f docker/docker-compose.yml down
endif

db-setup:
	@echo "Waiting for SQL Server to start..."
	sleep 10
	docker exec sealr-sqlserver /opt/mssql-tools18/bin/sqlcmd \
		-S localhost -U sa -P "Sealr@Dev123" -C \
		-Q "IF DB_ID('sealr') IS NULL CREATE DATABASE sealr"
	docker exec sealr-sqlserver /opt/mssql-tools18/bin/sqlcmd \
		-S localhost -U sa -P "Sealr@Dev123" -C -d sealr \
		-i /scripts/001_initial_schema.sql

# ─── Development ─────────────────────────
backend:
	cd backend && . venv/bin/activate && uvicorn app.main:app --reload --port 8000

frontend:
	cd frontend && npm run dev

worker:
	cd backend && . venv/bin/activate && celery -A app.workers.celery_app worker --loglevel=info

dev:
	@echo "Start each in a separate terminal:"
	@echo "  make backend"
	@echo "  make frontend"
	@echo "  make worker"

# ─── Testing ─────────────────────────────
test-backend:
	cd backend && . venv/bin/activate && python -m pytest tests/ -v

test-frontend:
	cd frontend && npm test

test: test-backend test-frontend

# ─── Linting ─────────────────────────────
lint:
	cd backend && . venv/bin/activate && ruff check .
	cd frontend && npx eslint .

# ─── Database Migrations ─────────────────
db-migrate:
	cd backend && . venv/bin/activate && alembic upgrade head

db-revision:
	cd backend && . venv/bin/activate && alembic revision --autogenerate -m "$(MSG)"

# ─── Cleanup ─────────────────────────────
clean:
	docker compose -f docker/docker-compose.yml down -v
	rm -rf backend/venv backend/__pycache__
	rm -rf frontend/node_modules frontend/.next
