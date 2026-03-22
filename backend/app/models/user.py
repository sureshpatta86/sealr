import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.utils.database import Base


class User(Base):
    __tablename__ = "Users"

    Id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    Email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    GitHubUsername: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False
    )
    GitHubTokenEncrypted: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False
    )
    PlanTier: Mapped[str] = mapped_column(
        String(20), nullable=False, default="free"
    )
    CreatedAt: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    UpdatedAt: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    IsActive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    repositories = relationship("Repository", back_populates="user")
    scans = relationship("Scan", back_populates="user")
    scan_configs = relationship("ScanConfig", back_populates="user")
