from sqlalchemy import Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.utils.database import Base


class SupportedLanguage(Base):
    __tablename__ = "SupportedLanguages"

    Id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    Language: Mapped[str] = mapped_column(String(50), nullable=False)
    Framework: Mapped[str] = mapped_column(String(100), nullable=False)
    DisplayName: Mapped[str] = mapped_column(String(100), nullable=False)
    ProjectFilePattern: Mapped[str] = mapped_column(String(200), nullable=False)
    BuildCommand: Mapped[str] = mapped_column(String(500), nullable=False)
    TestCommand: Mapped[str | None] = mapped_column(String(500), nullable=True)
    PackageManager: Mapped[str] = mapped_column(String(50), nullable=False)
    DockerImage: Mapped[str] = mapped_column(String(200), nullable=False)
    IsEnabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    SortOrder: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
