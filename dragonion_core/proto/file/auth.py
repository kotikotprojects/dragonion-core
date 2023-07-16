import sqlitedict


class AuthFile(sqlitedict.SqliteDict):
    """
    Valid AuthFile has fields:
    host - .onion url of service
    auth - v3 onion auth string in format, that can be written to .auth_private file
    """
    def __init__(self, service):
        super().__init__(
            filename=f'{service}.auth',
            tablename='auth',
            autocommit=True
        )
