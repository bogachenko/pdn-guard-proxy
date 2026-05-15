from fastapi import FastAPI
from pydantic import BaseModel, Field
from natasha import (
    Segmenter,
    NewsEmbedding,
    NewsNERTagger,
    MorphVocab,
    NamesExtractor,
    DatesExtractor,
    Doc,
)

app = FastAPI(title="Local PDN Detector Service")

segmenter = Segmenter()
embedding = NewsEmbedding()
ner_tagger = NewsNERTagger(embedding)
morph_vocab = MorphVocab()

names_extractor = NamesExtractor(morph_vocab)
dates_extractor = DatesExtractor(morph_vocab)

TECH_TERMS = {
    "api",
    "rest",
    "grpc",
    "http",
    "https",
    "json",
    "xml",
    "yaml",
    "jwt",
    "oauth",
    "oauth2",
    "sql",
    "nosql",
    "postgres",
    "postgresql",
    "mysql",
    "redis",
    "kafka",
    "docker",
    "kubernetes",
    "k8s",
    "golang",
    "go",
    "python",
    "java",
    "javascript",
    "typescript",
    "flutter",
    "dart",
    "react",
    "vue",
    "angular",
    "linux",
    "nginx",
    "grpcurl",
    "graphql",
    "restapi",
    "openapi",
    "swagger",
}


class AnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=262144)


class Entity(BaseModel):
    type: str
    start: int
    end: int


class AnalyzeResponse(BaseModel):
    has_entities: bool
    entities: list[Entity]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    entities: list[Entity] = []

    doc = Doc(req.text)
    doc.segment(segmenter)
    doc.tag_ner(ner_tagger)

    for span in doc.spans:
        if span.type not in {"PER", "LOC", "ORG"}:
            continue

        entity_text = req.text[span.start:span.stop]

        if is_safe_technical_term(entity_text):
            continue

        entities.append(
            Entity(
                type=span.type,
                start=span.start,
                end=span.stop,
            )
        )

    for match in names_extractor(req.text):
        start, end = get_match_bounds(match)

        if start < 0 or end <= start:
            continue

        if not is_strong_name_match(match):
            continue

        entity_text = req.text[start:end]

        if is_safe_technical_term(entity_text):
            continue

        entities.append(
            Entity(
                type="PER",
                start=start,
                end=end,
            )
        )

    for match in dates_extractor(req.text):
        start, end = get_match_bounds(match)

        if start < 0 or end <= start:
            continue

        entities.append(
            Entity(
                type="DATE",
                start=start,
                end=end,
            )
        )

    entities = dedupe_entities(entities)

    return AnalyzeResponse(
        has_entities=len(entities) > 0,
        entities=entities,
    )


def get_match_bounds(match) -> tuple[int, int]:
    if hasattr(match, "start") and hasattr(match, "stop"):
        return int(match.start), int(match.stop)

    if hasattr(match, "span"):
        span = match.span

        if hasattr(span, "start") and hasattr(span, "stop"):
            return int(span.start), int(span.stop)

        if isinstance(span, tuple) and len(span) == 2:
            return int(span[0]), int(span[1])

    return -1, -1


def is_strong_name_match(match) -> bool:
    fact = getattr(match, "fact", None)

    if fact is None:
        return False

    parts = 0

    if getattr(fact, "first", None):
        parts += 1

    if getattr(fact, "last", None):
        parts += 1

    if getattr(fact, "middle", None):
        parts += 1

    if getattr(fact, "nick", None):
        parts += 1

    return parts >= 2


def is_safe_technical_term(value: str) -> bool:
    normalized = (
        value.strip()
        .lower()
        .replace("-", "")
        .replace("_", "")
        .replace(".", "")
        .replace(" ", "")
    )

    if normalized in TECH_TERMS:
        return True

    if normalized.endswith("api") and len(normalized) <= 32:
        return True

    return False


def dedupe_entities(entities: list[Entity]) -> list[Entity]:
    seen: set[tuple[str, int, int]] = set()
    result: list[Entity] = []

    for entity in entities:
        key = (entity.type, entity.start, entity.end)
        if key not in seen:
            seen.add(key)
            result.append(entity)

    return result