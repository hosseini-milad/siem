from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pymongo import ReturnDocument

from app.api.access import User
from app.db.session import DB
from app.services.access import allowed, now, visible_task_lifetime

router = APIRouter(prefix='/api/v1', tags=['Tasks'])
CENTRAL = 'central'
DONE = 'done'
DEFAULT_COLUMNS = {
    'todo': {'title': 'برای انجام', 'position': 10},
    'doing': {'title': 'در حال انجام', 'position': 20},
    DONE: {'title': 'خاتمه‌یافته', 'position': 1000},
}
Priority = Literal['low', 'normal', 'high', 'urgent']
Identifier = Annotated[str, Field(pattern=r'^[a-zA-Z0-9_-]{1,64}$')]
Assignees = Annotated[list[Identifier], Field(min_length=1, max_length=20)]


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


class Column(Input):
    title: str = Field(min_length=1, max_length=60)
    position: int = Field(ge=1, le=999)
    audience: Literal['participants', 'branch', 'selected'] = 'participants'
    viewers: list[Identifier] = Field(default_factory=list, max_length=100)


class Tagged(Input):
    tags: list[str] | None = Field(default=None, max_length=8)

    @field_validator('tags')
    @classmethod
    def normalize_tags(cls, values):
        if values is None:
            return None
        labels = {}
        for value in values:
            label = value.strip()
            if not 1 <= len(label) <= 24:
                raise ValueError('Tags must contain 1–24 characters')
            labels.setdefault(label.casefold(), label)
        return list(labels.values())


class NewTask(Tagged):
    title: str = Field(min_length=1, max_length=120)
    description: str = Field(default='', max_length=4000)
    priority: Priority = 'normal'
    assignees: Assignees


class TaskUpdate(Tagged):
    revision: int = Field(ge=0)
    column_id: Identifier | None = None
    assignees: Assignees | None = None
    priority: Priority | None = None


class Comment(Input):
    text: str = Field(min_length=1, max_length=2000)


def own_board(user):
    if user['role'] == 'manager':
        return CENTRAL
    return user['_id'] if user['role'] == 'admin' else user['created_by']


def board_scope(user, board, database):
    if board == CENTRAL:
        if user['role'] == 'client':
            raise HTTPException(404, 'تابلو پیدا نشد.')
        return
    if user['role'] != 'manager' and board != own_board(user):
        raise HTTPException(404, 'تابلو پیدا نشد.')
    if not database.users.find_one({'_id': board, 'role': 'admin'}, {'_id': 1}):
        raise HTTPException(404, 'تابلو پیدا نشد.')


def is_supervisor(user, board):
    return user['role'] == 'manager' or (user['role'] == 'admin' and user['_id'] == board)


def columns(database, board):
    items = {key: {'id': key, 'audience': 'participants', **column}
             for key, column in DEFAULT_COLUMNS.items()}
    for row in database.task_columns.find({'board': board}):
        items[row['id']] = {key: row[key] for key in ('id', 'title', 'position', 'audience')}
        items[row['id']]['viewers'] = row.get('viewers', [])
    if DONE in items:
        items[DONE]['position'] = 1000
    return sorted(items.values(), key=lambda item: (item['position'], item['id']))


def participant(user):
    return {'$or': [{'creator': user['_id']}, {'assignees': user['_id']}]}


def visible_tasks(user, board, stages):
    scope = {'board': board, **visible_task_lifetime()}
    if not allowed(user, 'tasks'):
        return {**scope, 'assignees': user['_id']}
    if is_supervisor(user, board):
        return scope
    conditions = participant(user)['$or']
    if board != CENTRAL:
        conditions.append({'column_id': {'$in': [stage['id'] for stage in stages
            if stage['audience'] == 'branch' or (stage['audience'] == 'selected' and user['_id'] in stage['viewers'])]}})
    return {**scope, '$and': [{'$or': conditions}]}


def candidates(user, *, for_visibility=False):
    scope = {'active': True}
    if for_visibility:
        scope['permissions.tasks'] = {'$in': ['read', 'write']}
    if user['role'] == 'manager':
        return {**scope, 'role': 'admin'}
    return {**scope, 'role': 'client', 'created_by': own_board(user)}


def member_options(database, user, *, for_visibility=False):
    return [{'id': row['_id'], 'name': row['name'], 'username': row['username']}
            for row in database.users.find(candidates(user, for_visibility=for_visibility), {'name': 1, 'username': 1}).sort('name', 1)]


def validate_assignees(database, user, values, *, for_visibility=False):
    if len(set(values)) != len(values) or database.users.count_documents({
        **candidates(user, for_visibility=for_visibility), '_id': {'$in': values},
    }) != len(values):
        raise HTTPException(422, 'گیرندگان باید فعال، یکتا و در محدودهٔ مجاز ارجاع باشند.')


def fetch_task(database, user, task_id):
    task = database.tasks.find_one({'_id': task_id}, {'board': 1})
    if not task:
        raise HTTPException(404, 'تسک پیدا نشد.')
    board_scope(user, task['board'], database)
    stages = columns(database, task['board'])
    scope = visible_tasks(user, task['board'], stages)
    visible = database.tasks.find_one({'_id': task_id, **scope})
    if not visible:
        raise HTTPException(404, 'تسک پیدا نشد.')
    return visible, stages, scope


def task_view(task, user, names, include_comments=False):
    identity = user['_id']
    supervisor = is_supervisor(user, task['board'])
    write = allowed(user, 'tasks', write=True) or (
        'tasks' not in user.get('permissions', {}) and identity in task['assignees'])
    assignees = task['assignees']
    restricted = task['board'] == CENTRAL and user['role'] != 'manager'
    if restricted:
        assignees = [identity] if identity in assignees else []
    item = {key: task[key] for key in ('title', 'priority', 'column_id', 'created_at', 'closed_at', 'revision')}
    item.update(
        id=task['_id'], description=task['description'], tags=task.get('tags') or [],
        updated_by=editor_name(task, user, names),
        creator=names.get(task['creator'], '—'),
        assignees=[{'id': key, 'name': names.get(key, '—')} for key in assignees],
        comment_count=task['comment_count'],
        can_comment=write,
        can_move=write and task['closed_at'] is None and (
            supervisor or identity == task['creator'] or identity in task['assignees']),
        can_assign=write and task['closed_at'] is None and task['board'] == own_board(user) and (
            supervisor or identity == task['creator']),
    )
    if include_comments:
        item['comments'] = [{**comment, 'author': (
            'ادمین' if restricted and comment['author'] not in {identity, task['creator']}
            else names.get(comment['author'], '—'))} for comment in task['comments']]
    return item


def editor_name(task, user, names):
    editor = task.get('updated_by', task['creator'])
    if task['board'] == CENTRAL and user['role'] != 'manager' and editor not in {user['_id'], task['creator']}:
        return 'ادمین'
    return names.get(editor, '—')


def task_names(database, tasks):
    ids = set()
    for task in tasks:
        ids.update([task['creator'], task.get('updated_by', task['creator'])])
        ids.update(task['assignees'])
        ids.update(comment['author'] for comment in task.get('comments', ()))
    return {row['_id']: row['name'] for row in database.users.find({'_id': {'$in': list(ids)}}, {'name': 1})}


@router.get('/tasks/boards')
def boards(user: User, database: DB):
    if user['role'] == 'manager':
        rows = database.users.find({'role': 'admin'}, {'name': 1, 'branch': 1}).sort('branch', 1)
        return {'items': [{'id': CENTRAL, 'name': 'تابلوی مدیریت کل'}] + [
            {'id': row['_id'], 'name': row.get('branch') or row['name']} for row in rows]}
    owner = database.users.find_one({'_id': own_board(user)}, {'branch': 1})
    items = [{'id': own_board(user), 'name': (owner or {}).get('branch') or 'تابلوی شاخه'}]
    if user['role'] == 'admin':
        items.append({'id': CENTRAL, 'name': 'ارجاع‌های مدیریت کل'})
    return {'items': items}


@router.get('/tasks')
def list_tasks(user: User, database: DB, response: Response, board: Identifier,
               offset: int = Query(0, ge=0), limit: int = Query(60, ge=1, le=100)):
    board_scope(user, board, database)
    stages = columns(database, board)
    scope = visible_tasks(user, board, stages)
    rows = list(database.tasks.find(scope, {'comments': 0}).sort([('created_at', -1), ('_id', 1)]).skip(offset).limit(limit))
    names = task_names(database, rows)
    can_create = board == own_board(user) and allowed(user, 'tasks', write=True)
    response.headers['Cache-Control'] = 'no-store'
    return {'items': [task_view(task, user, names) for task in rows], 'columns': [{key: value for key, value in stage.items() if key != 'viewers'} for stage in stages],
            'total': database.tasks.count_documents(scope), 'offset': offset, 'limit': limit,
            'can_create': can_create, 'assignees': member_options(database, user) if can_create else []}


@router.post('/tasks', status_code=201)
def create_task(body: NewTask, user: User, database: DB):
    if not allowed(user, 'tasks', write=True):
        raise HTTPException(403, 'اجازهٔ ایجاد تسک را ندارید.')
    board = own_board(user)
    board_scope(user, board, database)
    validate_assignees(database, user, body.assignees)
    task = {'_id': uuid4().hex, **body.model_dump(), 'board': board, 'creator': user['_id'], 'updated_by': user['_id'],
            'column_id': 'todo', 'created_at': now(), 'closed_at': None, 'comments': [], 'comment_count': 0, 'revision': 0}
    database.tasks.insert_one(task)
    return task_view(task, user, task_names(database, [task]))


@router.get('/tasks/{task_id}')
def get_task(task_id: Identifier, user: User, database: DB, response: Response):
    task, _, _ = fetch_task(database, user, task_id)
    response.headers['Cache-Control'] = 'no-store'
    return task_view(task, user, task_names(database, [task]), include_comments=True)


@router.patch('/tasks/{task_id}')
def update_task(task_id: Identifier, body: TaskUpdate, user: User, database: DB):
    task, stages, scope = fetch_task(database, user, task_id)
    view = task_view(task, user, {})
    changes = body.model_dump(exclude_none=True, exclude={'revision'})
    if not changes:
        raise HTTPException(422, 'تغییری وارد نشده است.')
    if not view['can_move'] or (({'assignees', 'priority', 'tags'} & changes.keys()) and not view['can_assign']):
        raise HTTPException(403, 'اجازهٔ تغییر تسک را ندارید.')
    if body.assignees is not None:
        validate_assignees(database, user, body.assignees)
    if body.column_id is not None:
        if body.column_id not in {stage['id'] for stage in stages}:
            raise HTTPException(422, 'ستون مقصد در این تابلو وجود ندارد.')
        if body.column_id == DONE:
            changes['closed_at'] = now()
    changes['updated_by'] = user['_id']
    updated = database.tasks.find_one_and_update(
        {'_id': task_id, 'revision': body.revision, 'closed_at': None, **scope},
        {'$set': changes, '$inc': {'revision': 1}}, return_document=ReturnDocument.AFTER)
    if not updated:
        raise HTTPException(409, 'تسک تغییر کرده است. تابلو را تازه‌سازی کنید.')
    return task_view(updated, user, task_names(database, [updated]), include_comments=True)


@router.post('/tasks/{task_id}/comments', status_code=201)
def add_comment(task_id: Identifier, body: Comment, user: User, database: DB):
    task, _, scope = fetch_task(database, user, task_id)
    if not task_view(task, user, {})['can_comment']:
        raise HTTPException(403, 'اجازهٔ ثبت کامنت را ندارید.')
    comment = {'id': uuid4().hex, 'text': body.text, 'author': user['_id'], 'created_at': now()}
    updated = database.tasks.find_one_and_update({'_id': task_id, 'comments.199': {'$exists': False}, **scope},
        {'$push': {'comments': comment}, '$inc': {'comment_count': 1}, '$set': {'updated_by': user['_id']}}, return_document=ReturnDocument.AFTER)
    if not updated:
        raise HTTPException(409, 'تسک تغییر کرده یا به سقف ۲۰۰ کامنت رسیده است.')
    return task_view(updated, user, task_names(database, [updated]), include_comments=True)


def column_board(user):
    if user['role'] == 'client':
        raise HTTPException(403, 'مدیریت ستون‌ها مجاز نیست.')
    return own_board(user)


@router.get('/task-columns')
def list_columns(user: User, database: DB):
    board = column_board(user)
    return {'items': columns(database, board), 'allow_branch': board != CENTRAL,
            'members': member_options(database, user, for_visibility=True) if board != CENTRAL else []}


def save_column(body, user, database, column_id=None):
    board = column_board(user)
    stages = columns(database, board)
    if column_id is not None and column_id not in {stage['id'] for stage in stages}:
        raise HTTPException(404, 'ستون پیدا نشد.')
    if board == CENTRAL and body.audience != 'participants':
        raise HTTPException(422, 'ستون تابلوی مدیریت فقط برای اعضای تسک قابل مشاهده است.')
    if body.audience == 'selected':
        if not body.viewers:
            raise HTTPException(422, 'حداقل یک مشاهده‌کننده انتخاب کنید.')
        validate_assignees(database, user, body.viewers, for_visibility=True)
    elif body.viewers:
        raise HTTPException(422, 'فهرست مشاهده‌کنندگان فقط برای حالت انتخاب اعضا مجاز است.')
    identity = column_id or uuid4().hex
    values = {'id': identity, 'board': board, **body.model_dump()}
    if identity == DONE:
        values['position'] = 1000
    database.task_columns.update_one({'_id': f'{board}:{identity}'}, {'$set': values}, upsert=True)
    return {key: value for key, value in values.items() if key != 'board'}


@router.post('/task-columns', status_code=201)
def create_column(body: Column, user: User, database: DB):
    return save_column(body, user, database)


@router.patch('/task-columns/{column_id}')
def edit_column(column_id: Identifier, body: Column, user: User, database: DB):
    return save_column(body, user, database, column_id)
