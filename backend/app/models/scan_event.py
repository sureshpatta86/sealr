from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.utils.database import Base


class ScanEvent(Base):
    __tablename__ = "ScanEvents"

    Id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ScanId: Mapped[str] = mapped_column(
        String(36), ForeignKey("Scans.Id", ondelete="CASCADE"), nullable=False
    )
    EventType: Mapped[str] = mapped_column(String(50), nullable=False)
    WorkerName: Mapped[str | None] = mapped_column(String(50), nullable=True)
    Message: Mapped[str | None] = mapped_column(String(500), nullable=True)
    Metadata: Mapped[str | None] = mapped_column(Text, nullable=True)
    CreatedAt: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )

    scan = relationship("Scan", back_populates="events")
