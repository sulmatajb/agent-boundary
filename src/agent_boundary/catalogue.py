"""Fixed operation/resource catalogue.

Model JSON cannot add operations, resources, hosts, or secret names. A pair
outside this set is invalid input. A pair inside it is admitted only when every
ancestor capability lists that same pair.
"""

RESOURCES = frozenset({"source", "draft", "private", "env", "signup-net"})
OPERATIONS = frozenset({
    "document.read", "document.append", "secret.list", "network.probe",
})

# Document resources stay logical names. `env` and `signup-net` are fixture
# names too: they are not the process environment and not a network address.
CATALOGUE = frozenset({
    ("document.read", "source"),
    ("document.read", "draft"),
    ("document.read", "private"),
    ("document.append", "source"),
    ("document.append", "draft"),
    ("document.append", "private"),
    ("secret.list", "env"),
    ("network.probe", "signup-net"),
})

# Labels returned by the reference secret.list tool. Not credentials.
FIXTURE_SECRET_NAMES = ("FIXTURE_SIGNUP_KEY",)
