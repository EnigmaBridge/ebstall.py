"""
The module describes which operations can be done with strings in YAQL.
"""

import string as string_module

from yaql.language.factory import OperatorType

from ebstall import versions
import six

from yaql.language import specs
from yaql.language import utils
from yaql.language import yaqltypes


class VersionType(yaqltypes.PythonType):
    """
    Type representing a version
    """

    __slots__ = tuple()

    def __init__(self, nullable=False):
        super(VersionType, self).__init__(versions.Version, nullable=nullable)

    def convert(self, value, receiver, context, function_spec, engine,
                *args, **kwargs):
        value = super(VersionType, self).convert(
            value, receiver, context, function_spec, engine, *args, **kwargs)
        return None if value is None else versions.Version(value)


@specs.name('v')
def v(x):
    """:yaql:x
    """
    return versions.Version(x)


@specs.parameter('left', VersionType())
@specs.parameter('right', VersionType())
@specs.name('#operator_>')
def gt(left, right):
    """:yaql:operator >
    """
    return left > right


@specs.parameter('left', VersionType())
@specs.parameter('right', VersionType())
@specs.name('#operator_<')
def lt(left, right):
    """:yaql:operator <
    """
    return left < right


@specs.parameter('left', VersionType())
@specs.parameter('right', VersionType())
@specs.name('#operator_>=')
def gte(left, right):
    """:yaql:operator >=
    """
    return left >= right


@specs.parameter('left', VersionType())
@specs.parameter('right', VersionType())
@specs.name('#operator_<=')
def lte(left, right):
    """:yaql:operator <=
    """
    return left <= right


@specs.parameter('left', VersionType())
@specs.parameter('right', VersionType())
@specs.name('#operator_=')
def eq(left, right):
    """:yaql:operator =
    """
    return left == right


@specs.parameter('left', VersionType())
@specs.parameter('right', VersionType())
@specs.name('#operator_!=')
def neq(left, right):
    """:yaql:operator !=
    """
    return left != right


@specs.name('#unary_operator_v')
def vop(x):
    """:yaql:operator v
    """
    return versions.Version(str(x))


def register_factory(factory):
    """
    Registers all combols to the factory
    :param factory: 
    :return: 
    """
    factory.insert_operator(None, None, new_operator='v', new_operator_type=OperatorType.PREFIX_UNARY,
                            create_group=False)


def register(context, parser=None):
    """
    Registers all functions to the context
    :param context: 
    :param parser: 
    :return: 
    """
    context.register_function(gt)
    context.register_function(lt)
    context.register_function(gte)
    context.register_function(lte)
    context.register_function(eq)
    context.register_function(neq)
    context.register_function(v)
    context.register_function(vop)

    context.register_function(versions.version_len, name='version_len')
    context.register_function(versions.version_trim, name='version_trim')
    context.register_function(versions.version_pad, name='version_pad')
    context.register_function(versions.version_cmp, name='version_cmp')


