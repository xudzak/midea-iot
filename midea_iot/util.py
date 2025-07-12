from caterpillar.py import Transformer


class Bcd(Transformer):
    def encode(self, obj: str, context) -> bytes:
        result = []
        for i in range(0, len(obj), 2):
            high_char = obj[i]
            low_char = obj[i + 1] if i + 1 < len(obj) else "0"

            high_value = (
                ord(high_char) - ord("0")
                if "0" <= high_char <= "9"
                else ord(high_char) - ord("A") + 10
            )
            low_value = (
                ord(low_char) - ord("0")
                if "0" <= low_char <= "9"
                else ord(low_char) - ord("A") + 10
            )
            result.append((high_value << 4) | low_value)
        return bytes(result)

    def decode(self, parsed: bytes, context) -> str:
        chars = []
        for byte in parsed:
            c_lower = byte & 0b00001111
            c_upper = (byte & 0b11110000) >> 4
            if c_upper > 9:  # '\t'
                chars.append(chr(0x41 + c_upper - 10))
            else:
                chars.append(chr(0x30 + c_upper))

            if c_lower > 9:  # '\t'
                chars.append(chr(0x41 + c_lower - 10))
            else:
                chars.append(chr(0x30 + c_lower))

        return "".join(chars)
