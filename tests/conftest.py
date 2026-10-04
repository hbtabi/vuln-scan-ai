import random
import string

import pytest


@pytest.fixture
def fake():
    """Build secret-shaped strings at runtime so no literal token ever lives in the repo."""
    rng = random.Random(99)

    def make(prefix: str, n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
        return prefix + "".join(rng.choice(alphabet) for _ in range(n))

    return make
