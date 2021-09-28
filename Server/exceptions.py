class HeaderMissing(Exception):
    def __init__(self, info):
        super().__init__(f'Protocol exception:\n{info}')


class PayloadMissing(Exception):
    def __init__(self, info):
        super().__init__(f'Protocol exception:\n{info}')


class UnknownOperation(Exception):
    def __init__(self, info):
        super().__init__(f'Protocol exception:\n{info}')


class SentToFewBytes(Exception):
    def __init__(self, info):
        super().__init__(f'Connection exception:\n{info}')


class ReceivedToFewBytes(Exception):
    def __init__(self, info):
        super().__init__(f'Connection exception:\n{info}')
