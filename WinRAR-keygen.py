import hashlib
import sys
import zlib


def GF_2_n_table(n: int):
    ORDER: int = 2**n - 1
    log_table: list[int] = [0] * 2**n
    exp_table: list[int] = [0] * 2**n
    exp_table[0] = 1
    for i in range(1, ORDER):
        exp_table[i] = exp_table[i - 1] * 2
        if exp_table[i] >= 2**n:
            exp_table[i] ^= 2**n + 3
    exp_table[ORDER] = ~exp_table[ORDER]
    for i in range(ORDER):
        log_table[exp_table[i]] = i
    return ORDER, exp_table, log_table


class FieldType:
    ORDER, exp_table, log_table = GF_2_n_table(15)

    def __init__(self, array: list[int]):
        self.array = array

    def __add__(self, other: "FieldType"):
        return FieldType([i ^ j for i, j in zip(self.array, other.array)])

    def __sub__(self, other: "FieldType"):
        return self + other

    def __mul__(self, other: "FieldType"):
        """a * b mod (x¹⁵ + x + 1, y¹⁷ + y³ + 1)"""
        if self == other:
            return __class__.square(self.array)
        result = __class__.full_multiply_schoolbook(self.array, other.array)
        __class__.modular_reduction(result)
        return FieldType(result)

    def __truediv__(self, other: "FieldType"):
        return self * FieldType(__class__.inverse(other.array))

    def __pow__(self, n: int):
        result = FieldType.from_int(1, len(self.array))
        base = self
        while n != 0:
            if n % 2 == 1:
                result *= base
            base = __class__.square(base.array)
            n //= 2
        return result

    def __eq__(self, other: object):
        if not isinstance(other, FieldType):
            return False
        return int(self) == int(other)

    def __int__(self):
        result: int = 0
        for i, j in enumerate(self.array):
            result += j * ((__class__.ORDER + 1) ** i)
        return result

    def __str__(self):
        return f"{int(self):#x}"

    @classmethod
    def from_int(cls, value: int, length: int):
        array = [0] * length
        for i in range(length):
            array[i] = (value // ((cls.ORDER + 1) ** i)) % (cls.ORDER + 1)
        return cls(array)

    @classmethod
    def square(cls, a: list[int]):
        result = [0] * (len(a) * 2 - 1)
        for i in range(len(a)):
            if a[i] == 0:
                result[2 * i] = 0
                continue
            g = cls.log_table[a[i]] * 2
            if g >= cls.ORDER:
                g -= cls.ORDER
            result[2 * i] = cls.exp_table[g]
        for i in range(1, len(result), 2):
            result[i] = 0
        cls.modular_reduction(result)
        return FieldType(result)

    @classmethod
    def full_multiply_schoolbook(cls, a: list[int], b: list[int]):
        """a * b"""
        result = [0] * (len(a) + len(b) - 1)
        for i in range(len(a)):
            if a[i] == 0:
                continue
            for j in range(len(b)):
                if b[j] == 0:
                    continue
                g = cls.log_table[a[i]] + cls.log_table[b[j]]
                if g >= cls.ORDER:
                    g -= cls.ORDER
                result[i + j] ^= cls.exp_table[g]
        return result

    @classmethod
    def modular_reduction(cls, a: list[int]):
        """irreducible polynomial of extension field y¹⁷ + y³ + 1"""
        reduced_len = len(a) // 2 + 1
        for i in range(len(a) - 1, reduced_len - 1, -1):
            if a[i] != 0:
                a[i - reduced_len] ^= a[i]
                a[i - reduced_len + 3] ^= a[i]
            a.pop()

    @classmethod
    def inverse(cls, a: list[int]):
        if all(i == 0 for i in a):
            raise ValueError("Cannot invert zero")
        degs = {"b": 0, "c": 0, "e": 0, "f": len(a)}
        b = [0] * (2 * len(a))
        b[0] = 1
        c = [0] * (2 * len(a))
        e = a.copy() + [0] * len(a)
        for i in range(len(a) - 1, 0, -1):
            if a[i] != 0:
                degs["e"] = i
                break
        f = [0] * (2 * len(a))
        f[0] = f[3] = f[len(a)] = 1
        result = [0] * len(a)
        while True:
            if degs["e"] == 0:
                for i in range(degs["b"] + 1):
                    if b[i] == 0:
                        continue
                    g = cls.log_table[b[i]] - cls.log_table[e[0]]
                    if g < 0:
                        g += cls.ORDER
                    result[i] = cls.exp_table[g]
                break
            if degs["e"] < degs["f"]:
                b, c = c, b
                degs["b"], degs["c"] = degs["c"], degs["b"]
                e, f = f, e
                degs["e"], degs["f"] = degs["f"], degs["e"]
            offset = degs["e"] - degs["f"]
            g = cls.log_table[e[degs["e"]]] - cls.log_table[f[degs["f"]]]
            if g < 0:
                g += cls.ORDER
            alpha = cls.exp_table[g]
            log_alpha = cls.log_table[alpha]

            def add_scale(a: list[int], b: list[int], deg_a_str: str, deg_b_str: str):
                for i in range(degs[deg_b_str] + 1):
                    if b[i] == 0:
                        continue
                    g = log_alpha + cls.log_table[b[i]]
                    if g >= cls.ORDER:
                        g -= cls.ORDER
                    a[i + offset] ^= cls.exp_table[g]
                    if a[i + offset] != 0 and i + offset > degs[deg_a_str]:
                        degs[deg_a_str] = i + offset
                while a[degs[deg_a_str]] == 0:
                    degs[deg_a_str] -= 1

            add_scale(e, f, "e", "f")
            add_scale(b, c, "b", "c")
        return result


class MyCurve:
    """y² + xy = x³ + ax² + b"""

    def __init__(self, a: FieldType, b: FieldType):
        self.a = a
        self.b = b

    def __eq__(self, other: object):
        if not isinstance(other, MyCurve):
            return False
        return self.a == other.a and self.b == other.b

    def __str__(self):
        return f"y² + xy = x³ + {self.a}·x² + {self.b}"


class MyPoint:
    def __init__(
        self, curve: MyCurve, x: FieldType, y: FieldType, is_inf: bool = False
    ):
        if not is_inf and y**2 + x * y != x**3 + curve.a * x**2 + curve.b:
            raise ValueError(
                f"Point ({x}, {y}) is not on curve y² + xy = x³ + {curve.a}·x² + {curve.b}"
            )
        self.curve = curve
        self.x = x
        self.y = y
        self.is_inf = is_inf

    def double(self):
        """point doubling"""
        if self.is_inf:
            return self
        k = self.y / self.x + self.x
        x = k**2 + k + self.curve.a
        y = self.x**2 + (k + FieldType.from_int(1, 17)) * x
        return MyPoint(self.curve, x, y)

    def __add__(self, other: "MyPoint"):
        """point addition"""
        if self.curve != other.curve:
            raise ValueError("Cannot add points from different curves")
        if self == other:
            return self.double()
        if self.is_inf:
            return other
        if other.is_inf:
            return self
        k = (self.y + other.y) / (self.x + other.x)
        x = k**2 + k + self.x + other.x + self.curve.a
        y = k * (x + self.x) + x + self.y
        return MyPoint(self.curve, x, y)

    def __mul__(self, n: int):
        """point multiplication"""
        result = MyPoint(self.curve, FieldType([]), FieldType([]), is_inf=True)
        if n == 0 or self.is_inf:
            return result
        add = self
        while n:
            if n % 2 == 1:
                result += add
            add = add.double()
            n //= 2
        return result

    def __eq__(self, other: object):
        if not isinstance(other, MyPoint):
            return False
        if self.is_inf and other.is_inf:
            return True
        if self.is_inf or other.is_inf:
            return False
        return self.x == other.x and self.y == other.y

    def __str__(self):
        return f"({self.x}, {self.y})"


CURVE = MyCurve(FieldType.from_int(0, 17), FieldType.from_int(161, 17))
X = FieldType([
        0x38CC, 0x052F, 0x2510, 0x45AA, 0x1B89, 0x4468,
        0x4882, 0x0D67, 0x4FEB, 0x55CE, 0x0025, 0x4CB7,
        0x0CC2, 0x59DC, 0x289E, 0x65E3, 0x56FD,
    ])
Y = FieldType([
        0x31A7, 0x65F2, 0x18C4, 0x3412, 0x7388, 0x54C1,
        0x539B, 0x4A02, 0x4D07, 0x12D6, 0x7911, 0x3B5E,
        0x4F0E, 0x216F, 0x2BF2, 0x1974, 0x20DA,
    ])
GENERATOR_POINT = MyPoint(CURVE, X, Y)
ORDER = 0x1026DD85081B82314691CED9BBEC30547840E4BF72D8B5E0D258442BBCD31
USER_NAME = sys.argv[1]
AUTH_TYPE = sys.argv[2]


def get_generator(s: str):
    if s:
        sha1 = hashlib.sha1()
        sha1.update(s.encode())
        generator = [sha1.digest()[i * 4 : (i + 1) * 4][::-1] for i in range(5)]
    else:
        generator = map(
            lambda i: i.to_bytes(4, "little"),
            (0xEB3EB781, 0x50265329, 0xDC5EF4A3, 0x6847B9D5, 0xCDE43B4C),
        )
    return b"".join(generator)


def get_hash_and_rand(s: str, generator: bytes):
    sha1 = hashlib.sha1()
    sha1.update(s.encode())
    generator += (
        b"".join([sha1.digest()[i * 4 : (i + 1) * 4][::-1] for i in range(5)])
        + b"\x43\x8d\xfd\x0f\x7c\x3c\xe3\xb4\xd1\x1b\x46\x53\x46\xa5\x27\x0f\x0d\xd9\x50\x10"
    )
    hash = int.from_bytes(generator[20:50], "little")
    rand = b""
    for i in range(16, 31):
        sha1 = hashlib.sha1()
        sha1.update(i.to_bytes(4, "little") + generator)
        rand += sha1.digest()[3:1:-1]
    rand = int.from_bytes(rand, "little")
    return hash, rand


def get_private_key(generator: bytes):
    private_key = b""
    for i in range(1, 16):
        sha1 = hashlib.sha1()
        sha1.update(i.to_bytes(4, "little") + generator)
        private_key += sha1.digest()[3:1:-1]
    return int.from_bytes(private_key, "little")


def get_public_key(private_key: int):
    public_key = GENERATOR_POINT * private_key
    return 2 * int(public_key.x) + (int(public_key.y / public_key.x) & 1)


def get_signature(private_key: int, hash: int, rand: int):
    r = (int((GENERATOR_POINT * rand).x) + hash) % ORDER
    s = (rand - private_key * r) % ORDER
    return r, s


data = [""] * 4

empty_generator = get_generator("")
hash, rand = get_hash_and_rand(AUTH_TYPE, empty_generator)
empty_private_key = get_private_key(empty_generator)
r, s = get_signature(empty_private_key, hash, rand)
data[1] = f"60{s:060x}{r:060x}"

generator = get_generator(USER_NAME)
private_key = get_private_key(generator)
public_key = get_public_key(private_key)
public_key_hex = f"{public_key:064x}"
data[3] = f"60{public_key_hex[:48]}"

generator = get_generator(data[3])
private_key = get_private_key(generator)
public_key = get_public_key(private_key)
data[0] = f"{public_key:064x}"

uid = public_key_hex[48:] + data[0][:4]

hash, rand = get_hash_and_rand(USER_NAME + data[0], empty_generator)
r, s = get_signature(empty_private_key, hash, rand)
data[2] = f"60{s:060x}{r:060x}"

data_str = "".join(data)
checksum_str = AUTH_TYPE + USER_NAME + data_str
checksum = ~zlib.crc32(checksum_str.encode()) & 0xFFFFFFFF
data_str = "".join(str(len(s)) for s in data) + data_str + f"{checksum:010}"

with open("rarreg.key", "x") as key_file:
    print("RAR registration data", file=key_file)
    print(USER_NAME, file=key_file)
    print(AUTH_TYPE, file=key_file)
    print(f"UID={uid}", file=key_file)
    for i in range(0, len(data_str), 54):
        print(data_str[i : i + 54], file=key_file)
