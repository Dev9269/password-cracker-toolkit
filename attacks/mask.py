import itertools
from cracker.hash_detector import HashDetector


CHARSET_MAP = {
    "?l": "abcdefghijklmnopqrstuvwxyz",
    "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "?d": "0123456789",
    "?s": r"!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~",
    "?a": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    + r"!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~",
    "?b": "".join(chr(i) for i in range(256)),
}


def parse_mask(mask, custom_charsets=None):
    custom_charsets = custom_charsets or {}
    expanded = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            token = mask[i : i + 2]
            if token in CHARSET_MAP:
                expanded.append(CHARSET_MAP[token])
            elif token in custom_charsets:
                expanded.append(custom_charsets[token])
            else:
                expanded.append(token[1])
            i += 2
        else:
            expanded.append(mask[i])
            i += 1
    return expanded


def mask_keyspace_size(mask, custom_charsets=None):
    charsets = parse_mask(mask, custom_charsets)
    size = 1
    for cs in charsets:
        size *= len(cs)
    return size


def mask_candidates(mask, custom_charsets=None):
    charsets = parse_mask(mask, custom_charsets)
    for combo in itertools.product(*charsets):
        yield "".join(combo)


def keyspace_chunk(start, count, charsets):
    produced = 0
    for combo in itertools.islice(itertools.product(*charsets), start, start + count):
        yield "".join(combo)
        produced += 1
        if produced >= count:
            break


class MaskAttack:
    def __init__(self):
        self.hash_detector = HashDetector()

    def attack(
        self,
        hash_string,
        hash_type,
        mask,
        increment_callback,
        salt=None,
        salt_position="append",
        custom_charsets=None,
        **kwargs,
    ):
        custom_charsets = custom_charsets or {}
        charsets = parse_mask(mask, custom_charsets)
        try:
            for candidate in itertools.product(*charsets):
                password = "".join(candidate)
                increment_callback(1)
                if salt is not None:
                    hashed = self.hash_detector.hash_string(
                        password,
                        hash_type,
                        salt=salt,
                        salt_position=salt_position,
                        **kwargs,
                    )
                else:
                    hashed = self.hash_detector.hash_string(password, hash_type)
                if hashed == hash_string:
                    return {"success": True, "password": password, "attempts": 0}
            return {"success": False, "error": "Exhausted mask keyspace"}
        except (ValueError, MemoryError, OverflowError) as e:
            return {"success": False, "error": f"Mask attack error: {str(e)}"}
