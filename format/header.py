

class Header():
    def __init__(self, id, prefix, suffix):
        self._id = id
        self._prefix = prefix
        self._suffix = suffix
        self._values = list()

    @property
    def id(self):
        return self._id

    @property
    def prefix(self):
        return self._prefix

    @property
    def suffix(self):
        return self._suffix

    @property
    def values(self):
        return self._values

    def generate(self):
        value = self._header_prefix
        for value in values:
            value += value.generate()
        value += self._header_suffix

        return value

    def __str__(self):
        return "{} = {}".format(self._id, str([str(v) for v in self._values]))
