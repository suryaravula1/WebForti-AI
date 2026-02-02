from __future__ import annotations

from webforti_common.model_client import ModelClient, build_model_client
from webforti_common.models import CVERecord, GenerationPlan
from webforti_common.settings import Settings


def create_generation_plan(cve: CVERecord, context: list[dict], model_client: ModelClient) -> GenerationPlan:
    raw_plan = model_client.create_generation_plan(cve, context)
    return GenerationPlan.from_mapping(raw_plan)


def create_generation_plan_from_settings(cve: CVERecord, context: list[dict], settings: Settings) -> GenerationPlan:
    return create_generation_plan(cve, context, build_model_client(settings))
