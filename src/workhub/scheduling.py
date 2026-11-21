import json
import re

from sqlalchemy import select

from workhub.domain import HubError
from workhub.models import Attempt, Repository, Task, TaskDependency


def declared_dependencies(task, repository):
    matches = re.findall(r"<!--\s*workhub:\s*(.*?)\s*-->", task.spec.get("body", ""), re.DOTALL)
    if not matches:
        return []
    if len(matches) != 1:
        raise HubError(422, "An issue may contain only one workhub metadata block")
    try:
        data = json.loads(matches[0])
        if not isinstance(data, dict) or set(data) - {"depends_on"}:
            raise ValueError()
        refs = data.get("depends_on", [])
        if not isinstance(refs, list) or len(refs) > 100:
            raise ValueError()
        result = []
        for ref in refs:
            if not isinstance(ref, str) or not re.fullmatch(
                r"(?:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)?#[1-9][0-9]*", ref
            ):
                raise ValueError()
            result.append(repository + ref if ref.startswith("#") else ref)
        return sorted(set(result))
    except (ValueError, TypeError) as exc:
        raise HubError(
            422,
            'Invalid dependency metadata; use <!-- workhub: {"depends_on":["owner/repo#42"]} -->',
        ) from exc


def graph(session):
    tasks = {t.id: t for t in session.scalars(select(Task))}
    repos = {r.id: r.full_name for r in session.scalars(select(Repository))}
    references = {
        f"{repos[t.repository_id]}#{t.issue_number}".lower(): t.id for t in tasks.values()
    }
    edges = {task_id: set() for task_id in tasks}
    missing = {task_id: [] for task_id in tasks}
    for task in tasks.values():
        for ref in declared_dependencies(task, repos[task.repository_id]):
            target = references.get(ref.lower())
            if target:
                edges[task.id].add(target)
            else:
                missing[task.id].append(ref)
    for dependency in session.scalars(select(TaskDependency)):
        edges[dependency.task_id].add(dependency.dependency_id)
    return tasks, edges, missing


def assert_acyclic(edges):
    visiting, visited = set(), set()

    def visit(task_id):
        if task_id in visiting:
            raise HubError(409, "Dependency cycle detected")
        if task_id in visited:
            return
        visiting.add(task_id)
        for dependency in edges.get(task_id, []):
            visit(dependency)
        visiting.remove(task_id)
        visited.add(task_id)

    for task_id in edges:
        visit(task_id)


def blockers(session, task_id):
    tasks, edges, missing = graph(session)
    return missing.get(task_id, []) + [
        dependency
        for dependency in sorted(edges.get(task_id, []))
        if tasks[dependency].state != "merged"
    ]


def set_dependencies(hub, task_id, dependencies):
    with hub.db.write() as session:
        task = session.get(Task, task_id)
        if not task:
            raise HubError(404, "Task not found")
        if task.state == "merged":
            raise HubError(409, "Merged task dependencies cannot be changed")
        tasks, edges, _ = graph(session)
        if any(dependency not in tasks for dependency in dependencies):
            raise HubError(404, "Dependency task not found")
        # Preserve dependencies approved in the issue body; admin edges are additional gates.
        for old in list(
            session.scalars(select(TaskDependency).where(TaskDependency.task_id == task_id))
        ):
            session.delete(old)
        session.flush()
        for dependency in sorted(set(dependencies)):
            session.add(TaskDependency(task_id=task_id, dependency_id=dependency))
        session.flush()
        _, edges, _ = graph(session)
        assert_acyclic(edges)
        for attempt in session.scalars(
            select(Attempt).where(Attempt.task_id == task_id, Attempt.state == "leased")
        ):
            attempt.state = "revoked"
            task.state, task.reason = "reconciling", "Dependencies changed; assignment revoked"
        hub.audit(
            session,
            "admin",
            "dependencies.updated",
            task_id,
            dependencies=sorted(set(dependencies)),
        )
    return {"task_id": task_id, "dependencies": sorted(set(dependencies))}
