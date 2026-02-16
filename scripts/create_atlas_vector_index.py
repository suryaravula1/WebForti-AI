from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from pymongo.errors import OperationFailure, PyMongoError
from pymongo.operations import SearchIndexModel

from webforti_common.settings import load_settings


DEFAULT_INDEX_PATH = Path("infrastructure/mongo/atlas_vector_index.json")
COLLECTION_NAME = "knowledge_documents"


def main() -> int:
    parser = argparse.ArgumentParser(description="Create the WebForti Atlas Vector Search index.")
    parser.add_argument("--index-file", default=str(DEFAULT_INDEX_PATH), help="Path to Atlas Search index JSON.")
    parser.add_argument("--wait", action="store_true", help="Wait until Atlas reports the index queryable.")
    parser.add_argument("--timeout-seconds", type=int, default=180, help="Maximum wait time when --wait is used.")
    args = parser.parse_args()

    settings = load_settings()
    index_path = Path(args.index_file)
    try:
        index_spec = json.loads(index_path.read_text(encoding="utf-8"))
        apply_runtime_embedding_settings(index_spec, settings)
    except FileNotFoundError:
        print(f"index file not found: {index_path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"index file is not valid JSON: {exc}", file=sys.stderr)
        return 2

    try:
        from pymongo import MongoClient
    except ImportError:
        print("pymongo is not installed. Install requirements.txt first.", file=sys.stderr)
        return 2

    client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=10000)
    collection = client[settings.mongo_database][COLLECTION_NAME]
    index_name = str(index_spec["name"])

    try:
        client.admin.command("ping")
        existing = list(collection.list_search_indexes(index_name))
        if existing:
            if index_definition_matches(existing[0], index_spec["definition"]):
                print(f"Atlas Search index '{index_name}' already exists on {settings.mongo_database}.{COLLECTION_NAME}.")
            else:
                collection.update_search_index(index_name, index_spec["definition"])
                print(
                    f"Updated Atlas Search index '{index_name}' on {settings.mongo_database}.{COLLECTION_NAME} "
                    f"for {settings.embedding_dimensions}D {settings.embedding_model} embeddings."
                )
        else:
            model = SearchIndexModel(
                definition=index_spec["definition"],
                name=index_name,
                type=index_spec.get("type", "vectorSearch"),
            )
            collection.create_search_index(model=model)
            print(f"Created Atlas Search index '{index_name}' on {settings.mongo_database}.{COLLECTION_NAME}.")
        if args.wait:
            wait_until_queryable(collection, index_name, args.timeout_seconds)
        return 0
    except OperationFailure as exc:
        print(format_operation_failure(exc, settings.mongo_database), file=sys.stderr)
        return 1
    except PyMongoError as exc:
        print(f"MongoDB operation failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()


def wait_until_queryable(collection: Any, index_name: str, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        indexes = list(collection.list_search_indexes(index_name))
        if indexes and bool(indexes[0].get("queryable")):
            print(f"Atlas Search index '{index_name}' is queryable.")
            return
        status = indexes[0].get("status", "unknown") if indexes else "missing"
        print(f"Waiting for '{index_name}' to become queryable; current status: {status}.")
        time.sleep(5)
    raise OperationFailure(f"Timed out waiting for Atlas Search index '{index_name}' to become queryable")


def format_operation_failure(exc: OperationFailure, database_name: str) -> str:
    message = str(exc)
    if "command not found" in message.lower() or "search indexes are not available" in message.lower():
        return (
            "Atlas Search index creation failed. This command requires MongoDB Atlas Search support; "
            f"confirm MONGO_URI points to an Atlas cluster and database '{database_name}' is accessible."
        )
    return f"Atlas Search index creation failed: {exc.__class__.__name__}: {message}"


def apply_runtime_embedding_settings(index_spec: dict[str, Any], settings: Any) -> None:
    for field in index_spec.get("definition", {}).get("fields", []):
        if field.get("type") == "vector" and field.get("path") == "embedding":
            field["numDimensions"] = settings.embedding_dimensions


def index_definition_matches(existing: dict[str, Any], desired: dict[str, Any]) -> bool:
    current_definition = existing.get("latestDefinition", existing.get("definition", {}))
    return current_definition.get("fields", []) == desired.get("fields", [])


if __name__ == "__main__":
    raise SystemExit(main())
