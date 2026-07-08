"""Skills library loader — searches Anthropic-Cybersecurity-Skills for relevant procedures."""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Resolve skills path relative to this file
_SKILLS_DIR = Path(__file__).resolve().parent.parent.parent / "Anthropic-Cybersecurity-Skills" / "skills"

# In-memory index: skill_name -> first ~200 chars of description from SKILL.md
_skills_index: dict[str, dict] | None = None


def _build_index() -> dict[str, dict]:
    """Build a lightweight index of all skills (name + description snippet)."""
    global _skills_index
    if _skills_index is not None:
        return _skills_index

    _skills_index = {}
    if not _SKILLS_DIR.exists():
        logger.warning("Skills directory not found: %s", _SKILLS_DIR)
        return _skills_index

    for skill_dir in _SKILLS_DIR.iterdir():
        if not skill_dir.is_dir():
            continue
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            continue
        try:
            text = skill_md.read_text(encoding="utf-8", errors="ignore")
            # Extract description from YAML frontmatter
            description = ""
            if text.startswith("---"):
                parts = text.split("---", 2)
                if len(parts) >= 3:
                    frontmatter = parts[1]
                    for line in frontmatter.split("\n"):
                        if line.startswith("description:"):
                            description = line.split(":", 1)[1].strip().strip("'\"")
                            break
                    # Also grab tags
                    tags = []
                    in_tags = False
                    for line in frontmatter.split("\n"):
                        if line.startswith("tags:"):
                            in_tags = True
                            continue
                        if in_tags:
                            if line.startswith("- "):
                                tags.append(line[2:].strip())
                            else:
                                in_tags = False

            _skills_index[skill_dir.name] = {
                "description": description,
                "tags": tags if 'tags' in dir() and tags else [],
                "path": str(skill_md),
            }
        except Exception as e:
            logger.debug("Failed to index skill %s: %s", skill_dir.name, e)

    logger.info("Indexed %d cybersecurity skills", len(_skills_index))
    return _skills_index


def find_relevant_skills(query: str, max_skills: int = 3) -> str:
    """Find skills relevant to a query and return their content as context.

    Uses simple keyword matching against skill names, descriptions, and tags.
    Returns concatenated skill summaries (truncated to keep context manageable).
    """
    index = _build_index()
    if not index:
        return ""

    query_lower = query.lower()
    query_words = set(query_lower.split())

    # Score each skill by keyword overlap
    scored = []
    for name, info in index.items():
        score = 0
        name_words = set(name.replace("-", " ").split())
        desc_lower = info["description"].lower()
        tags_text = " ".join(info.get("tags", [])).lower()
        searchable = f"{name.replace('-', ' ')} {desc_lower} {tags_text}"

        for word in query_words:
            if len(word) < 3:
                continue
            if word in searchable:
                score += 2
            # Partial match
            elif any(word in w for w in searchable.split()):
                score += 1

        if score > 0:
            scored.append((score, name, info))

    if not scored:
        return ""

    # Take top matches
    scored.sort(key=lambda x: x[0], reverse=True)
    top = scored[:max_skills]

    context_parts = []
    for _, name, info in top:
        try:
            skill_path = Path(info["path"])
            content = skill_path.read_text(encoding="utf-8", errors="ignore")
            # Strip YAML frontmatter
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    content = parts[2].strip()
            # Truncate to keep context manageable
            if len(content) > 2000:
                content = content[:2000] + "\n...(truncated)"
            context_parts.append(f"### Skill: {name}\n{content}")
        except Exception:
            continue

    return "\n\n".join(context_parts)
