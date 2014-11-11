# -*- coding: utf-8 -*-
"""
Pyvac User Management Views.

Used by the connected user to edit its account.
"""
import base64

from pyramid.settings import asbool

from pyvac.models import User
from pyvac.helpers.i18n import trans as _
from pyvac.helpers.ldap import LdapCache
from pyvac.helpers.util import extract_cn

from .account import AccountMixin
from .base import EditView, View


class UserMixin(AccountMixin):
    redirect_route = 'home'

    def get_model(self):
        return self.user

    def update_view(self, model, view):
        pass


class Edit(UserMixin, EditView):
    """
    Edit connected user
    """


class ChangePassword(UserMixin, EditView):
    """
    Change current user password
    """

    def validate(self, model, errors):
        r = self.request

        if not User.by_credentials(self.session, model.login,
                                   r.params['current_password']):
            errors.append(_(u'current password is not correct'))
        elif r.params['user.password'] == r.params['current_password']:
            errors.append(_(u'password is inchanged'))

        if r.params['user.password'] != r.params['confirm_password']:
            errors.append(_(u'passwords do not match'))

        return len(errors) == 0


class Whoswho(View):

    def render(self):

        settings = self.request.registry.settings
        use_ldap = False
        if 'pyvac.use_ldap' in settings:
            use_ldap = asbool(settings.get('pyvac.use_ldap'))

        users = User.find(self.session)
        ldap_users = {}
        if use_ldap:
            # synchronise user groups/roles
            User.sync_ldap_info(self.session)
            ldap = LdapCache()
            ldap_users = ldap.list_users()

            for user in users:
                ldap_user = ldap_users.get(user.dn, {})
                user.nickname = ldap_user.get('uid', ['-'])[0]
                user.mobile = ldap_user.get('mobile', ['-'])[0]
                user.unit = extract_cn(ldap_user.get('ou', ['-'])[0])
                if user.manager_dn:
                    user.name_manager = extract_cn(user.manager_dn)
                else:
                    user.name_manager = '-' or user.manager.name
                jpegPhoto = ldap_user.get('jpegPhoto')
                photo = None
                if jpegPhoto:
                    photo = base64.b64encode(jpegPhoto[0])
                user.photo = photo

        return {u'user_count': User.find(self.session, count=True),
                u'users': users,
                }
