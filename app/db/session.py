from typing import Annotated

from fastapi import Depends, Request
from pymongo.database import Database


def get_database(request: Request) -> Database:
    return request.app.state.database


DB = Annotated[Database, Depends(get_database)]
