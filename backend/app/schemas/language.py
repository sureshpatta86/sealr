from pydantic import BaseModel


class LanguageResponse(BaseModel):
    id: int
    language: str
    framework: str
    display_name: str
    project_file_pattern: str
    build_command: str
    test_command: str | None
    package_manager: str
    docker_image: str
    is_enabled: bool
    sort_order: int

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, lang) -> "LanguageResponse":
        return cls(
            id=lang.Id,
            language=lang.Language,
            framework=lang.Framework,
            display_name=lang.DisplayName,
            project_file_pattern=lang.ProjectFilePattern,
            build_command=lang.BuildCommand,
            test_command=lang.TestCommand,
            package_manager=lang.PackageManager,
            docker_image=lang.DockerImage,
            is_enabled=lang.IsEnabled,
            sort_order=lang.SortOrder,
        )
