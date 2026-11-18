from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from app.db.session import DB
from app.schemas.siem import RuleCreate, RuleToggle
from app.services import detections, siem

router = APIRouter(prefix='/api/v1')


@router.post('/detections/rules', tags=['Detection Rules'], status_code=201, summary='ساخت قاعدهٔ شمارش رویداد به تفکیک منبع')
def create_rule(body: RuleCreate, database: DB):
    return siem.create(database.siem_rules, body.model_dump())


@router.get('/detections/rules', tags=['Detection Rules'])
def rules(database: DB, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100000)):
    return siem.page(database.siem_rules, {}, limit, offset)


@router.put('/detections/rules/{rule_id}', tags=['Detection Rules'], summary='ویرایش تعریف قاعده')
def replace_rule(rule_id: UUID, body: RuleCreate, database: DB):
    result = database.siem_rules.update_one({'_id': str(rule_id)}, {'$set': {**body.model_dump(), 'updated_at': siem.now()}})
    if not result.matched_count:
        raise HTTPException(404, 'Rule not found')
    return siem.public(database.siem_rules.find_one({'_id': str(rule_id)}))


@router.patch('/detections/rules/{rule_id}', tags=['Detection Rules'], summary='فعال یا غیرفعال‌کردن قاعده')
def toggle_rule(rule_id: UUID, body: RuleToggle, database: DB):
    result = database.siem_rules.update_one({'_id': str(rule_id)}, {'$set': {'enabled': body.enabled, 'updated_at': siem.now()}})
    if not result.matched_count:
        raise HTTPException(404, 'Rule not found')
    return siem.public(database.siem_rules.find_one({'_id': str(rule_id)}))


@router.post('/detections/evaluate', tags=['Detection Rules'], summary='ارزیابی دستی قواعد فعال و تولید هشدار با کنترل تکرار')
def evaluate(database: DB):
    return detections.evaluate_rules(database)


@router.get('/detections/rules/{rule_id}', tags=['Detection Rules'])
def rule(rule_id: UUID, database: DB):
    row = siem.public(database.siem_rules.find_one({'_id': str(rule_id)}))
    if row is None:
        raise HTTPException(404, 'Rule not found')
    return row
