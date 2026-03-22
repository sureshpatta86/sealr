import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.utils.database import Base


class Repository(Base):
    __tablename__ = "Repositories"

    Id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    UserId: Mapped[str] = mapped_column(
        String(36), ForeignKey("Users.Id"), nullable=False
    )
    GitHubUrl: Mapped[str] = mapped_column(String(500), nullable=False)
    Owner: Mapped[str] = mapped_column(String(100), nullable=False)
    Name: Mapped[str] = mapped_column(String(100), nullable=False)
    DefaultBranch: Mapped[str] = mapped_column(
        String(100), nullable=False, default="main"
    )
    Language: Mapped[str | None] = mapped_column(String(50), nullable=True)
    Framework: Mapped[str | None] = mapped_column(String(100), nullable=True)
    LastScannedAt: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    CreatedAt: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )

    user = relationship("User", back_populates="repositories")
    scans = relationship("Scan", back_populates="repository")
