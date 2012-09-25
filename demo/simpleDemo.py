#!/usr/bin/env python
#encoding=utf-8

'''
flaskext-principal演示程序
适用于原版的flaskext-principal
'''

import os
import sys
try:
    #在没有安装flaskext-principal只下载了我fork的项目源码的情况下需要这
    #样增加一个搜索路径,否则flaskext-principal将无法引入
    sys.path.append('../')
except:
    pass
import datetime

from flask import Flask, Response, session, request, redirect, url_for
from flaskext.principal import Principal, Permission, RoleNeed, ActionNeed, PermissionDenied, identity_changed, identity_loaded, Identity

app = Flask(__name__)
#配置app参数
app.config.update(
    #使用session必须要配置secret key
    SECRET_KEY=os.urandom(32).encode('hex')
)
#集成principal支持
principal = Principal(app)
#配置某种操作的权限
sayHiPermission = Permission(ActionNeed('sayHi'))
#配置登录用户权限,只要用户登录了就授予该权限
loginPermission = Permission(RoleNeed('loginUser'))
#配置某角色权限
adminRolePermission = Permission(RoleNeed('adminRole'))


#设置无权限处理器
@app.errorhandler(PermissionDenied)
def permissionDenied(error):
    print '该操作(' + request.url + ')需要的访问权限为:' + str(error.args[0].needs)
    #先记录来源地址
    session['redirected_from'] = request.url
    #如果用户已登录则显示无权限页面
    if session.get('identity.name'):
        return '访问被拒绝!<br/>该问该页面(' + request.url + ')需要的权限是' + str(error.args[0].needs) + ',目前用户拥有的权限是' + str(session.get('identity').provides)
    #如果用户还未登录则转向到登录面
    return redirect(url_for('login'))


#权限绑定处理器,将登录过的赋予其对应的权限
#将该操作与identity_loaded信号绑定,identity装载成功后即赋权
@identity_loaded.connect
def permissionHandler(sender, identity):
    #先给登录用户赋予通用权限
    identity.provides.add(RoleNeed('loginUser'))
    #不同的用户赋予不同的权限
    if identity.name == 'admin':
        print '赋予adminRole权限给' + identity.name
        identity.provides.add(RoleNeed('adminRole'))
    if identity.name != 'admin':
        print '赋予sayHi权限给' + identity.name
        identity.provides.add(ActionNeed('sayHi'))
    else:
        pass


@principal.identity_loader
def loadIdentityFromSession():
    #每收到一次request请求便从会话中获取身份信息(如果有的话)
    #按照principal的实现机制,每次请求的方法执行先都会先调用
    #principal.identity_loader装饰的方法,从会话中取出
    #identity.name和identity.auth_type来构造一个新的identity
    if 'identity' in session:
        return session.get('identity')


@principal.identity_saver
def saveIdentityToSession(identity):
    #按principal的实现机制,identity将在与其对应的权限关联后(即
    #对identity.provides赋值后调用principal.identity_saver装饰
    #的方法保存identity信息到会话中,但只保存identity.name和
    #identity.auth_type
    session['identity.name'] = identity.name
    session['identity.auth_type'] = identity.auth_type
    session['identity'] = identity


@app.route('/')
def index():
    if session.get('identity.name'):
        str = 'welcome, ' + session.get('identity.name') + ', <a href="logout">log out</a><br/>'
    else:
        str = 'you are not login in--><a href="login">login </a><br/>'
    return Response('''
                    <DOCTYPE HTML>
                    <html>
                    <head><title>flaskext-principal demo</title></head>
                    <body>
                        <center>
                        ''' + str + '''
                        <a href="sayHi">sayHi(for user who had "sayHi" permission)</a><br/>
                        <a href="datetime">datetime(for those who had login in)</a><br/>
                        <a href="admin">admin page(for those who had an "adminRole" permission)</a>
                    </body>
                    </html>
                    ''')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return Response('''
                        <form name="login" action="" method="post">
                            username:<input name="username" type="text"/><br/>
                            password:<input name="password" type="password"/><br/>
                            <input type="submit" value="login"/>
                        ''')
    else:
        username = request.form['username']
        #password = request.form['password']
        #用户认证
        #认证成功后发信号通知pincipal
        identity = Identity(username)
        identity_changed.send(app, identity=identity)
        redirected_from = session.get('redirected_from')
        print redirected_from, url_for('login')
        if redirected_from and not redirected_from.endswith(url_for('login')):
                #如果有记录来源页且来源页非登录页,则转向到来源页
                return redirect(redirected_from)
        #否则转向到首页
        return redirect(url_for('index'))


@app.route('/logout')
def logout():
    for key in ['identity', 'identity.name', 'identity.auth_type', 'directed_from']:
        try:
            del session[key]
        except:
            pass
    #登出后统一转向到首页
    return redirect(url_for('index'))


@app.route('/sayHi')
@sayHiPermission.require()
def sayHi():
    return Response('you will see this page only if have a \'sayHi\' permission')


@app.route('/datetime')
@loginPermission.require()
def currentDateTime():
    return Response('only logined users could see me:' + str(datetime.datetime.now()))


@app.route('/admin')
@adminRolePermission.require()
def admin():
    return Response('you can view this page only if you are a admin role')

if __name__ == '__main__':
    reload(sys)
    sys.setdefaultencoding('utf-8')
    app.run(debug=True)
