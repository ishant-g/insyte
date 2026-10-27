"""Optional project grouping around scans."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.errors import NotFoundError
from app.models.target import Project
from app.schemas.project import ProjectCreate, ProjectRead, ProjectUpdate
from app.schemas.scan import ScanListItem
from app.services.scan.service import ScanService

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)) -> ProjectRead:
    project = Project(name=payload.name, description=payload.description)
    db.add(project)
    db.commit()
    db.refresh(project)
    return ProjectRead.model_validate(project)


@router.get("", response_model=list[ProjectRead])
def list_projects(db: Session = Depends(get_db)) -> list[ProjectRead]:
    from sqlalchemy import select

    rows = db.scalars(select(Project).order_by(Project.created_at.desc())).all()
    return [ProjectRead.model_validate(r) for r in rows]


@router.get("/{project_id}", response_model=ProjectRead)
def get_project(project_id: uuid.UUID, db: Session = Depends(get_db)) -> ProjectRead:
    project = db.get(Project, project_id)
    if project is None:
        raise NotFoundError("Project not found")
    return ProjectRead.model_validate(project)


@router.put("/{project_id}", response_model=ProjectRead)
def update_project(
    project_id: uuid.UUID, payload: ProjectUpdate, db: Session = Depends(get_db)
) -> ProjectRead:
    project = db.get(Project, project_id)
    if project is None:
        raise NotFoundError("Project not found")
    if payload.name is not None:
        project.name = payload.name
    if payload.description is not None:
        project.description = payload.description
    db.commit()
    db.refresh(project)
    return ProjectRead.model_validate(project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def delete_project(project_id: uuid.UUID, db: Session = Depends(get_db)) -> None:
    project = db.get(Project, project_id)
    if project is None:
        raise NotFoundError("Project not found")
    db.delete(project)
    db.commit()


@router.get("/{project_id}/scans", response_model=list[ScanListItem])
def list_project_scans(project_id: uuid.UUID, db: Session = Depends(get_db)) -> list[ScanListItem]:
    svc = ScanService(db)
    rows, _total = svc.list(project_id=project_id, limit=200)
    return [ScanListItem.model_validate(r) for r in rows]
