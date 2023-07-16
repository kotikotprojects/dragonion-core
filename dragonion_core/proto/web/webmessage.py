from typing import Literal, Final, Union
from dataclasses_json import dataclass_json
from dataclasses import dataclass


webmessage_type_literal = Literal[
    "connect", "message", "disconnect", "error", "notification"
]
webmessage_error_message_literal = Literal[
    "unknown", "username_exists", "invalid_webmessage"
]


@dataclass_json
@dataclass
class _WebAnyMessage:
    username: str | None = None
    type: webmessage_type_literal = "message"
    message: str | None = None
    error_message: webmessage_error_message_literal | None = None


@dataclass_json
@dataclass
class WebMessageMessage:
    username: str
    message: str
    type: Final = "message"


@dataclass_json
@dataclass
class WebErrorMessage:
    error_message: webmessage_error_message_literal
    type: Final = "error"


@dataclass_json
@dataclass
class WebUserMessage:
    type: Literal["connect", "disconnect"]
    username: str


@dataclass_json
@dataclass
class WebNotificationMessage:
    message: str
    type: Final = "notification"


webmessages_union = Union[
    WebMessageMessage,
    WebErrorMessage,
    WebUserMessage,
    WebNotificationMessage
]


class WebMessage:
    @staticmethod
    def from_json(data) -> webmessages_union:
        return {
            "connect": WebUserMessage.from_json,
            "disconnect": WebUserMessage.from_json,
            "message": WebMessageMessage.from_json,
            "error": WebErrorMessage.from_json,
            "notification": WebNotificationMessage.from_json
        }[_WebAnyMessage.from_json(data).type](data)
