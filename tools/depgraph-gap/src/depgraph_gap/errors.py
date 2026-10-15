class DepgraphGapError(Exception):
    pass


class InvalidRepository(DepgraphGapError):
    pass


class MissingToken(DepgraphGapError):
    pass


class MissingTool(DepgraphGapError):
    pass


class ToolFailed(DepgraphGapError):
    pass


class DependencyGraphDisabled(DepgraphGapError):
    pass


class MalformedBom(DepgraphGapError):
    pass


class ConversionLoss(DepgraphGapError):
    pass


class LosslessInvariantViolation(DepgraphGapError):
    pass
