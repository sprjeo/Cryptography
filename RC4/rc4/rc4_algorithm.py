class RC4:
    def __init__(self, key: bytes):
        self.S = list(range(256))
        self.key = key
        self._initialize_state()

    def _initialize_state(self):
        j = 0
        for i in range(256):
            j = (j + self.S[i] + self.key[i % len(self.key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    def _keystream(self):
        i = j = 0
        while True:
            i = (i + 1) % 256
            j = (j + self.S[i]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
            yield self.S[(self.S[i] + self.S[j]) % 256]

    def process(self, data: bytes) -> bytes:
        stream = self._keystream()
        return bytes(b ^ next(stream) for b in data)
