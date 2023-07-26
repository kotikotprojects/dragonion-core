from typing import Literal, Union
from dataclasses_json import dataclass_json
from dataclasses import dataclass
from datetime import datetime

from .server import (
    webmessage_error_message_literal,
    WebErrorMessage,
    WebNotificationMessage
)
from .connection import (
    WebDisconnectMessage,
    WebConnectionMessage,
    WebConnectionResultMessage
)
from .message import (
    WebMessageMessage,
    WebBroadcastableMessage
)

__all__ = [
    'webmessage_type_literal',
    'webmessages_union',
    'WebMessage',

    'WebMessageMessage',
    'WebBroadcastableMessage',

    'webmessage_error_message_literal',
    'WebErrorMessage',
    'WebNotificationMessage',

    'WebDisconnectMessage',
    'WebConnectionMessage',
    'WebConnectionResultMessage'
]

webmessage_type_literal = Literal[
    "connect", "connect_answer", "disconnect",
    "broadcastable", "message",
    "error", "notification",
]


@dataclass_json
@dataclass
class _WebAnyMessage:
    username: str | None = None
    type: webmessage_type_literal = "message"
    password: str | None = None
    avatar: str | None = None
    message: str | None = None
    messages: dict[str, WebMessageMessage] = None
    error_message: webmessage_error_message_literal | None = None
    time: datetime = None


webmessages_union = Union[
    WebMessageMessage,
    WebBroadcastableMessage,
    WebErrorMessage,
    WebConnectionMessage,
    WebDisconnectMessage,
    WebNotificationMessage,
    WebConnectionResultMessage
]


class WebMessage:
    """
    Class for handling incoming webmessages
    """

    @staticmethod
    def from_json(data) -> webmessages_union:
        """
        Restores webmessage object from json
        :param data: Valid json data
        :return: One of types from webmessages_union
        """
        return {
            "connect": WebConnectionMessage.from_json,
            "disconnect": WebDisconnectMessage.from_json,
            "message": WebMessageMessage.from_json,
            "error": WebErrorMessage.from_json,
            "notification": WebNotificationMessage.from_json,
            "connect_answer": WebConnectionResultMessage.from_json,
            "broadcastable": WebBroadcastableMessage.from_json
        }[_WebAnyMessage.from_json(data).type](data)
