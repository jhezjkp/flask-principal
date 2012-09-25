# -*- coding: utf-8 -*-
"""
    flaskext.principal
    ~~~~~~~~~~~~~~~~~~

    Identity management for Flask.

    :copyright: (c) 2010-2011 by Ali Afshar.
    :copyright: (c) 2011 by Alfred Hall.
    :license: MIT, see LICENSE for more details.

    注释参考资料：
        1、stackoverflow.com[http://stackoverflow.com/questions/7050137/\
           flask-principal-tutorial-auth-authr]
"""

import sys
from functools import partial, wraps
from collections import namedtuple, deque


from flask import g, session, current_app, abort
from flask.signals import Namespace


signals = Namespace()
"""Namespace for principal's signals.
"""


identity_changed = signals.signal('identity-changed', doc=(
    """Signal sent when the identity for a request has been changed.

Actual name: ``identity-changed``

Authentication providers should send this signal when authentication has been
successfully performed. Flask-IdentityContext connects to this signal and
causes the identity to be saved in the session.
即用户认证成功时要发送一次该信号并将对应的Identity作为参数传入，对应地，
Principal将把该Identity信息保存到会话中

For example::

    from flaskext.principal import Identity, identity_changed

    def login_view(req):
        username = req.form.get('username')
        # check the credentials
        identity_changed.send(app, identity=Identity(username))
"""))


identity_loaded = signals.signal('identity-loaded', doc=(
    """Signal sent when the identity has been initialised for a request.

Actual name: ``identity-loaded``

Identity information providers should connect to this signal to perform two
major activities:

    1. Populate the identity object with the necessary authorization
       provisions.
    2. Load any additional user information.
Identity信息提供方应该在接收到该信息后至少要做以下两个操作：
    1、给认证成功的Identity植入对应的授权信息
    2、装载额外的用户信息(这些信息将以identity属性的形式被存储到会话中)

For example::

    from flaskext.principal import indentity_loaded, RoleNeed, UserNeed

    @identity_loaded.connect
    def on_identity_loaded(sender, identity):
        # Get the user information from the db
        user = db.get(identity.name)
        # Update the roles that a user can provide
        for role in user.roles:
            identity.provides.add(RoleNeed(role.name))
        # Save the user somewhere so we only look it up once
        identity.user = user
"""))


Need = namedtuple('Need', ['method', 'value'])
"""A required need

This is just a named tuple, and practically any tuple will do.

The ``method`` attribute can be used to look up element 0, and the ``value``
attribute can be used to look up element 1.
"""

#特定用户授权
UserNeed = partial(Need, 'name')
UserNeed.__doc__ = """A need with the method preset to `"name"`."""

#特定角色授权
RoleNeed = partial(Need, 'role')
RoleNeed.__doc__ = """A need with the method preset to `"role"`."""

#特定类型授权
TypeNeed = partial(Need, 'type')
TypeNeed.__doc__ = """A need with the method preset to `"role"`."""

#特定操作授权
ActionNeed = partial(Need, 'action')
TypeNeed.__doc__ = """A need with the method preset to `"action"`."""

#特定数据项授权
ItemNeed = namedtuple('RowNeed', ['method', 'value', 'type'])
"""A required item need

An item need is just a named tuple, and practically any tuple will do. In
addition to other Needs, there is a type, for example this could be specified
as::

    RowNeed('update', 27, 'posts')
    ('update', 27, 'posts') # or like this

And that might describe the permission to update a particular blog post. In
reality, the developer is free to choose whatever convention the permissions
are.
"""


#该异常将在用户尝试做一个无权限的操作时抛出
class PermissionDenied(RuntimeError):
    """Permission denied to the resource
    """


#身份
class Identity(object):
    """Represent the user's identity.

    :param name: The username
    :param auth_type: The authentication type used to confirm the user's
                      identity.

    The identity is used to represent the user's identity in the system. This
    object is created on login, or on the start of the request as loaded from
    the user's session.
    Identity对象在系统中用来代表用户身份。该对象一般中用户登录时创建或在每次
    发起request请求时从会话中装载。

    Once loaded it is sent using the `identity-loaded` signal, and should be
    populated with additional required information.
    Identity一旦装载后，它就将被名为“identity-loaded”的信号以参数的形式发送出
    去，并且框架将为它植入额外的必须信息(即授权信息、用户信息等)。

    Needs that are provided by this identity should be added to the `provides`
    set after loading.
    在装载后，对应的Needs信息应该被添加到该对象的一个名为“provides“的set中
    """
    def __init__(self, name, auth_type=''):
        self.name = name
        self.auth_type = auth_type

        self.provides = set()
        """A set of needs provided by this user

        Provisions can be added using the `add` method, for example::

            identity = Identity('ali')
            identity.provides.add(('role', 'admin'))
        """

    def can(self, permission):
        """Whether the identity has access to the permission.

        :param permission: The permission to test provision for.
        """
        return permission.allows(self)


#匿名用户
class AnonymousIdentity(Identity):
    """An anonymous identity

    :attr name: `"anon"`
    """

    def __init__(self):
        Identity.__init__(self, 'anon')


#认证上下文管理器
class IdentityContext(object):
    """The context of an identity for a permission.

    .. note:: The principal is usually created by the
              flaskext.Permission.require method call for normal use-cases.

    The principal behaves as either a context manager or a decorator. The
    permission is checked for provision in the identity, and if available the
    flow is continued (context manager) or the function is executed
    (decorator).
    """

    def __init__(self, permission, http_exception=None):
        #调用permission的require方法时，该上下文将被实例化
        self.permission = permission
        self.http_exception = http_exception
        """The permission of this principal
        """

    #@property将其修饰的函数以“属性”方式调用，调用instance.identity等价于
    #调用instance.identity()
    @property
    def identity(self):
        """The identity of this principal
        """
        return g.identity

    def can(self):
        """Whether the identity has access to the permission
        """
        return self.identity.can(self.permission)

    def __call__(self, f):
        @wraps(f)
        def _decorated(*args, **kw):
            self.__enter__()
            exc = (None, None, None)
            try:
                result = f(*args, **kw)
            except Exception:
                exc = sys.exc_info()
            self.__exit__(*exc)
            return result
        return _decorated

    def __enter__(self):
        # check the permission here
        if not self.can():
            #如果无权限访问
            if self.http_exception:
                #且指明了无权限时要抛出的异常代码，则调用abort
                abort(self.http_exception, self.permission)
            #在未指明无权限时要抛出的异常代码的情况下，抛出PermissionDenied
            raise PermissionDenied(self.permission)

    def __exit__(self, *exc):
        if exc != (None, None, None):
            cls, val, tb = exc
            raise(cls, val, tb)
        return False


class Permission(object):
    """Represents needs, any of which must be present to access a resource

    :param needs: The needs for this permission
    """
    def __init__(self, *needs):
        """A set of needs, any of which must be present in an identity to have
        access.
        """

        self.needs = set(needs)
        self.excludes = set()

    def __nonzero__(self):
        """Equivalent to ``self.can()``.
        """
        return bool(self.can())

    def __and__(self, other):
        """Does the same thing as ``self.union(other)``
        """
        return self.union(other)

    def __or__(self, other):
        """Does the same thing as ``self.difference(other)``
        """
        return self.difference(other)

    def __contains__(self, other):
        """Does the same thing as ``other.issubset(self)``.
        """
        return other.issubset(self)

    def require(self, http_exception=None):
        """Create a principal for this permission.

        The principal may be used as a context manager, or a decroator.

        If ``http_exception`` is passed then ``abort()`` will be called
        with the HTTP exception code. Otherwise a ``PermissionDenied``
        exception will be raised if the identity does not meet the
        requirements.

        :param http_exception: the HTTP exception code (403, 401 etc)
        由于permission未与identity耦合，因此在这必须调用identity上下文
        管理器来获取identity信息以判定该操作是否继续或抛出
        PermissionDenied(未指定http_exception值的情况下)或者调用abort
        方法并将http_exception值作为参数传入
        """
        return IdentityContext(self, http_exception)

    def test(self, http_exception=None):
        """
        Checks if permission available and raises relevant exception
        if not. This is useful if you just want to check permission
        without wrapping everything in a require() block.

        This is equivalent to::

            with permission.require():
                pass
        """

        with self.require(http_exception):
            pass

    def reverse(self):
        """
        Returns reverse of current state (needs->excludes, excludes->needs)
        """

        p = Permission()
        p.needs.update(self.excludes)
        p.excludes.update(self.needs)
        return p

    def union(self, other):
        """Create a new permission with the requirements of the union of this
        and other.

        :param other: The other permission
        """
        p = Permission(*self.needs.union(other.needs))
        p.excludes.update(self.excludes.union(other.excludes))
        return p

    def difference(self, other):
        """Create a new permission consisting of requirements in this
        permission and not in the other.
        """

        p = Permission(*self.needs.difference(other.needs))
        p.excludes.update(self.excludes.difference(other.excludes))
        return p

    def issubset(self, other):
        """Whether this permission needs are a subset of another

        :param other: The other permission
        """
        return self.needs.issubset(other.needs) and self.excludes.issubset(other.excludes)

    def allows(self, identity):
        """Whether the identity can access this permission.

        :param identity: The identity
        判定一个identity是否对某permission拥有访问权限要同时满足两个条件：
            1、permission允许的Need集合(存储于permission对象的needs属性中)与identity被授权的Need集合(存储于
               identity对象的provides属性中)有交集
            2、permission拒绝的Need集合(存储于permission对象的excludes属性中)与identity被授权的Need集合(存储于
               identity对象的provides属性中)没有交集
        """
        if self.needs and not self.needs.intersection(identity.provides):
            return False

        if self.excludes and self.excludes.intersection(identity.provides):
            return False

        return True

    def can(self):
        """Whether the required context for this permission has access

        This creates an identity context and tests whether it can access this
        permission
        """
        return self.require().can()


class Denial(Permission):
    """
    Shortcut class for passing excluded needs.
    """

    def __init__(self, *excludes):
        self.excludes = set(excludes)
        self.needs = set()


def session_identity_loader():
    '''从会话中获取身份信息(如果有的话)'''
    if 'identity.name' in session and 'identity.auth_type' in session:
        identity = Identity(session['identity.name'],
                            session['identity.auth_type'])
        return identity


def session_identity_saver(identity):
    '''将身份信息保存到会话中'''
    session['identity.name'] = identity.name
    session['identity.auth_type'] = identity.auth_type
    session.modified = True


class Principal(object):
    """Principal extension

    :param app: The flask application to extend
    :param use_sessions: Whether to use sessions to extract and store
                         identification.
    """
    def __init__(self, app=None, use_sessions=True):
        self.identity_loaders = deque()
        self.identity_savers = deque()
        # XXX This will probably vanish for a better API
        self.use_sessions = use_sessions
        if app is not None:
            self._init_app(app)

    def _init_app(self, app):
        #将_on_before_request方法注册到app的请求前置处理器，每次请求前都会
        #执行该方法
        app.before_request(self._on_before_request)
        #将“identity_changed”信号与_on_identity_changed方法关联，app以参数
        #形式传入，使得每收到一个“identity_changed”信号时，
        #_on_identity_changed方法都将关联执行
        identity_changed.connect(self._on_identity_changed, app)

        if self.use_sessions:
            #如果使用会话，则添加一个默认的identity装载器和一个默认的
            #identity存储器
            self.identity_loader(session_identity_loader)
            self.identity_saver(session_identity_saver)

    def set_identity(self, identity):
        """Set the current identity.

        :param identity: The identity to set
        """
        self._set_thread_identity(identity)
        for saver in self.identity_savers:
            saver(identity)

    def identity_loader(self, f):
        """Decorator to define a function as an identity loader.

        An identity loader function is called before request to find any
        provided identities. The first found identity is used to load from.

        For example::

            app = Flask(__name__)

            principals = Principal(app)

            @principals.identity_loader
            def load_identity_from_weird_usecase():
                return Identity('ali')
        """
        self.identity_loaders.appendleft(f)
        return f

    def identity_saver(self, f):
        """Decorator to define a function as an identity saver.

        An identity loader saver is called when the identity is set to persist
        it for the next request.

        For example::

            app = Flask(__name__)

            principals = Principal(app)

            @principals.identity_saver
            def save_identity_to_weird_usecase(identity):
                my_special_cookie['identity'] = identity
        """
        self.identity_savers.appendleft(f)
        return f

    def _set_thread_identity(self, identity):
        g.identity = identity
        identity_loaded.send(current_app._get_current_object(),
                             identity=identity)

    def _on_identity_changed(self, app, identity):
        self.set_identity(identity)

    def _on_before_request(self):
        #该方法在每次请求前都执行一次
        #为当前请求的全局变量，是flask中的
        g.identity = AnonymousIdentity()
        #领取取出identity_loaders中的身份装载器(用于从会话中[或其他方式]获取identity)
        for loader in self.identity_loaders:
            identity = loader()
            if identity is not None:
                #装载到一个有效的identity就持有它
                self.set_identity(identity)
                #不再调用后面的装载器
                return
