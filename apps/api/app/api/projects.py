"""Project / Workspace endpoints for multi-tenant isolation."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from app.dependencies import get_repositories
from app.infrastructure.db.repository import Repositories

router = APIRouter(prefix="/api/projects", tags=["projects"])


class CreateProjectRequest(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=128)
    description: str = Field(default="")


@router.get("")
def list_projects(repos: Repositories = Depends(get_repositories)) -> list[dict[str, Any]]:
    """List all projects in the workspace."""
    projects = repos.projects.list()
    if not projects:
        # Auto-seed default project if empty
        repos.projects.create("default", "Default Project", "Default workspace project")
        projects = repos.projects.list()
    return projects


@router.post("", status_code=status.HTTP_201_CREATED)
def create_project(
    payload: CreateProjectRequest,
    repos: Repositories = Depends(get_repositories),
) -> dict[str, Any]:
    """Create a new project workspace."""
    existing = repos.projects.get(payload.project_id)
    if existing is not None:
        return existing
    return repos.projects.create(payload.project_id, payload.name, payload.description)
