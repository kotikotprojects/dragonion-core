from dataclasses import dataclass
from dataclasses_json import dataclass_json

from datetime import datetime

from typing import Final


@dataclass_json
@dataclass
class WebConnectionMessage:
    """
    Sent when user is connected (sent by user)
    :param username: Username of connected
    :param public_key: b64-encoded rsa public key
    """
    username: str
    public_key: bytes
    password: str
    type: Final = "connect"
    time: datetime = None


@dataclass_json
@dataclass
class WebConnectionResultMessage:
    """
    Sent by server as answer to user connected
    :param connected_users: Dict with public keys in format username:public_key
    """
    connected_users: dict[str, bytes] = None
    type: Final = "connect_answer"
    time: datetime = None


@dataclass_json
@dataclass
class WebDisconnectMessage:
    """
    Sent when user is disconnected
    :param username: Username of disconnected
    """
    username: str
    type: Final = "disconnect"
    time: datetime = None
