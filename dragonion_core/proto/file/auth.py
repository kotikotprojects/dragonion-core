import sqlitedict


class AuthFile(sqlitedict.SqliteDict):
    """
    Valid AuthFile has fields:
    host - .onion url of service
    auth - v3 onion auth string in format, that can be written to .auth_private file
    """
    def __init__(self, service):
        """
        :param service: Service name or service.auth filename
        """
        super().__init__(
            filename=f'{service}.auth' if '.auth' not in service else service,
            tablename='auth',
            autocommit=True
        )
