class HeaderValue():
    def __init__(self, prefix, suffix, value):
        self._prefix = prefix
        self._suffix = suffix
        self._value = value

    @property
    def prefix(self):
        return self._prefix

    @property
    def suffix(self):
        return self._suffix

    @property
    def value(self):
        return self._value

    @property
    def generate(self):
        return self._prefix + self._value + self._suffix

    def __str__(self):
        return str(self._value)
