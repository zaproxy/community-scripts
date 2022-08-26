#!/usr/bin/env python

import os
import time

try:
    from urllib import quote  # Python 2.X
except ImportError:
    from urllib.parse import quote  # Python 3+

ZAP_API_KEY = os.environ["ZAP_API_KEY"]
ZAP_URL = os.environ["ZAP_URL"]
ZAP_USERNAME = os.environ["ZAP_USERNAME"]
ZAP_PASSWORD = os.environ["ZAP_PASSWORD"]


def get_or_create_context(zap, context_name=""):
    if zap.context.context_list:
        for context in zap.context.context_list:
            if context == context_name:
                context_id = zap.context.context(context_name)["id"]
                break
        else:
            context_id = zap.context.new_context(contextname=context_name)
    else:
        context_id = zap.context.new_context(contextname=context_name)

    return context_id

def get_or_create_user(zap, context_id, name=""):
    if zap.users.users_list():
        for user in zap.users.users_list():
            if user["name"] == name:
                user_id = user["id"]
                break
        else:
            user_id = zap.users.new_user(contextid=context_id, name=name)
    else:
        user_id = zap.users.new_user(contextid=context_id, name=name)

    return user_id

def zap_started(zap, target):
    """
    zap_started hook
    """
    def set_include_in_context(context_name):
        exclude_urls = [
            f"{ZAP_URL}/auth.*",
        ]
        include_urls = [
            f"{ZAP_URL}.*",
        ]
        for url in include_urls:
            zap.context.include_in_context(context_name, url)

        for url in exclude_urls:
            zap.context.exclude_from_context(context_name, url)

    def set_logged_in_indicator():
        logged_in_regex = "\Q</app-logout>\E"
        logged_out_regex = "\Qname=\"login\"\E"
        context_id = get_or_create_context(zap, context_name="Example")
        zap.authentication.set_logged_in_indicator(context_id, logged_in_regex)
        zap.authentication.set_logged_out_indicator(context_id, logged_out_regex)

    def set_form_based_auth():
        context_id = get_or_create_context(zap, context_name="Example")
        login_url = f"{ZAP_URL}/auth/realms/example/protocol/openid-connect/token"
        login_request_data = "username={%username%}&password={%password%}&client_id=y-portal&grant_type=password"
        form_based_config = "loginUrl=" + quote(login_url) + "&loginRequestData=" + quote(login_request_data)
        zap.authentication.set_authentication_method(context_id, "formBasedAuthentication", form_based_config)

    def set_user_auth_config():
        user = f"{ZAP_USERNAME}"
        context_id = get_or_create_context(zap, context_name="Example")
        user_id = get_or_create_user(zap, context_id=context_id, name=user)
        user_auth_config = "username=" + quote(ZAP_USERNAME) + "&password=" + quote(ZAP_PASSWORD)
        zap.users.set_authentication_credentials(context_id, user_id, user_auth_config)
        zap.users.set_user_enabled(context_id, user_id, "true")
        zap.forcedUser.set_forced_user(context_id, user_id)
        zap.forcedUser.set_forced_user_mode_enabled("true")
        return user_id

    get_or_create_context(zap, context_name="Example")
    set_include_in_context(context_name="Example")
    set_form_based_auth()
    set_logged_in_indicator()
    set_user_auth_config()
    return zap, target

def zap_spider(zap, target):
    context_id = get_or_create_context(zap, context_name="Example")
    user_id = get_or_create_user(zap, context_id=context_id, name="Example")

    spider_scan_id = zap.spider.scan_as_user(
        url=target,
        contextid=context_id,
        userid=user_id,
        recurse=True
    )
    time.sleep(5)

    while (int(zap.spider.status(spider_scan_id)) < 100):
        time.sleep(5)

    return zap, target

def zap_active_scan(zap, target, policy):
    context_id = get_or_create_context(zap, context_name="Example")
    user_id = get_or_create_user(zap, context_id=context_id, name="Example")

    ascan_scan_id = zap.ascan.scan_as_user(
        target,
        contextid=context_id,
        userid=user_id,
        recurse=True,
        scanpolicyname=policy
    )
    time.sleep(5)

    while(int(zap.ascan.status(ascan_scan_id)) < 100):
        time.sleep(5)
