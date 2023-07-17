from typing import Literal, Final, Union
from dataclasses_json import dataclass_json
from dataclasses import dataclass, field
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

from ..encryption.identity import Identity

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
    """
    Sent as regular message
    :param username: From user
    :param message: Encrypted b64-encoded message
    """
    username: str
    message: bytes
    type: Final = "message"

    def decrypt(self, identity: Identity):
        return identity.decrypt(self.message)


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
class WebConnectionMessage:
    """
    Sent when user is connected (sent by user)
    :param username: Username of connected
    :param public_key: b64-encoded rsa public key
    """
    username: str
    public_key: bytes
    type = "connect"


@dataclass_json
@dataclass
class WebDisconnectMessage:
    """
    Sent when user is disconnected
    :param username: Username of disconnected
    """
    username: str
    type = "disconnect"


@dataclass_json
@dataclass
class WebNotificationMessage:
    """
    Sent from server name as unencrypted notification
    :param message: Message content, not encrypted
    """
    message: str
    type: Final = "notification"


webmessages_union = Union[
    WebMessageMessage,
    WebErrorMessage,
    WebConnectionMessage,
    WebDisconnectMessage,
    WebNotificationMessage
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
            "notification": WebNotificationMessage.from_json
        }[_WebAnyMessage.from_json(data).type](data)


@dataclass
class WebBroadcastableMessage:
    """
    Class for creating outcoming messages
    :param from_user: User, that send message
    :param message_content: Text of message
    :param keys: Dict with public keys in format username:public_key
    """
    from_user: str
    message_content: str
    keys: dict[str, bytes]

    encrypted_messages: dict[str, webmessages_union] = field(default_factory=dict)

    def __post_init__(self):
        for username in self.keys.keys():
            public_key = serialization.load_der_public_key(
                base64.urlsafe_b64decode(self.keys[username])
            )
            self.encrypted_messages[username] = WebMessageMessage(
                username=self.from_user,
                message=base64.urlsafe_b64encode(public_key.encrypt(
                    self.message_content.encode(),
                    padding=padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ))
            )

    def json(self):
        return dict(
            map(
                lambda i, j: (i, j),
                self.encrypted_messages.keys(),
                [item.to_json() for item in self.encrypted_messages.values()]
            )
        )
