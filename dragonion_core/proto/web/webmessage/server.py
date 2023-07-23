from dataclasses import dataclass
from dataclasses_json import dataclass_json
from typing import Final, Literal


webmessage_error_message_literal = Literal[
    "unknown", "username_exists", "invalid_webmessage"
]


@dataclass_json
@dataclass
class WebErrorMessage:
    """
    Sent when error on server occurs
    :param error_message: See webmessage_error_message_literal
    """
    error_message: webmessage_error_message_literal
    type: Final = "error"


@dataclass_json
@dataclass
class WebNotificationMessage:
    """
    Sent from server name as unencrypted notification
    :param message: Message content, not encrypted
    """
    message: str
    type: Final = "notification"
