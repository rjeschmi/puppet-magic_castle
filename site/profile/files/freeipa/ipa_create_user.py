#!/usr/bin/env python
import argparse
import grp
import os
import pwd
import shutil
import stat
import sys

from glob import glob

from selinux import chcon, security_getenforce
from python_freeipa import ClientMeta
from python_freeipa.exceptions import DuplicateEntry


def add_users(client, users, password, shell, home_prefix):
    for user in users:
        home_path = os.path.join(home_prefix, user)
        user_input = {
            "a_uid": user,
            "o_givenname": user,
            "o_sn": user,
            "o_cn": user,
            "o_loginshell": shell,
            "o_random": True,
        }
        if os.path.exists(home_path):
            stat_info = os.stat(home_path)
            user_input["o_uidnumber"] = stat_info.st_uid
            user_input["o_gidnumber"] = stat_info.st_gid
        try:
            user_info = client.user_add(**user_input)["result"]
        except DuplicateEntry:
            pass
        else:
            client.change_password(user, password, user_info["randompassword"])


def add_groups(client, groups):
    for group in groups:
        try:
            client.group_add(group)
        except DuplicateEntry:
            pass


def add_users_to_groups(client, users, groups):
    for group in groups:
        client.group_add_member(a_cn=group, o_user=users)


def create_home(users, home_prefix, selinux_enforce, selinux_context):
    skel_files = glob("/etc/skel/*") + glob("/etc/skel/.*")
    for user in users:
        home = os.path.join(home_prefix, user)
        if not os.path.exists(home):
            pwdnam = pwd.getpwnam(user)
            uid = pwdnam.pw_uid
            gid = pwdnam.pw_gid
            os.mkdir(home)
            os.chown(home, uid, gid)
            os.chmod(home, stat.S_IRWXU)
            if selinux_enforce:
                chcon(home, selinux_context)
            for src in skel_files:
                filename = src.split("/")[-1]
                dst = os.path.join(home, filename)
                shutil.copy(src, dst)
                os.chown(dst, uid, gid)
                os.chmod(dst, stat.S_IRWXU)
                if selinux_enforce:
                    chcon(src, selinux_context)


def create_project(users, groups, project_prefix, selinux_enforce, selinux_context):
    for group in groups:
        gid = grp.getgrnam(group).gr_gid
        project = os.path.join(project_prefix, str(gid))
        if not os.path.exists(project):
            os.mkdir(project)
            os.chown(project, 0, gid)
            os.chmod(project, stat.S_ISGID | stat.S_IRWXU | stat.S_IRWXG)
            os.symlink(project, os.path.join(project_prefix, group))
            if selinux_enforce:
                chcon(project, selinux_context)
        for user in users:
            pwdnam = pwd.getpwnam(user)
            uid = pwdnam.pw_uid
            project_user = os.path.join(project_prefix, str(gid), user)
            os.mkdir(project_user)
            os.chown(project_user, uid, gid)
            os.chmod(project_user, stat.S_ISGID | stat.S_IRWXU)
            if selinux_enforce:
                chcon(project, selinux_context)


def create_scratch(users, scratch_prefix, selinux_enforce, selinux_context):
    for user in users:
        scratch = os.path.join(scratch_prefix, user)
        if not os.path.exists(scratch):
            pwdnam = pwd.getpwnam(user)
            uid = pwdnam.pw_uid
            gid = pwdnam.pw_gid
            os.mkdir(scratch)
            os.chown(scratch, uid, gid)
            os.chmod(scratch, stat.S_IRWXU | stat.S_IRWXG)
            if selinux_enforce:
                chcon(scratch, selinux_context)


def create_home_symlinks(
    users,
    groups,
    home_prefix,
    project_prefix,
    scratch_prefix,
    selinux_enforce,
    selinux_context,
):
    for user in users:
        home = os.path.join(home_prefix, user)
        if os.path.exists(home):
            scratch = os.path.join(scratch_prefix, user)
            pwdnam = pwd.getpwnam(user)
            uid, gid = pwdnam.pw_uid, pwdnam.pw_gid
            home_projects = os.path.join(home, "projects")
            os.mkdir(home_projects)
            os.chown(home_projects, 0, gid)
            os.chmod(home_projects, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
            if selinux_enforce:
                chcon(home_projects, selinux_context)
            for group in groups:
                project = os.path.join(project_prefix, group)
                if os.path.exists(project):
                    os.symlink(project, os.path.join(home_projects, group))
            if os.path.exists(scratch):
                os.symlink(scratch, os.path.join(home, "scratch"))


def main(
    admin_password,
    users,
    password,
    groups,
    shell,
    chroot,
    home_prefix,
    project_prefix,
    scratch_prefix,
    enable_create_home,
    enable_create_project,
    enable_create_scratch,
    enable_create_home_symlinks,
    selinux_context,
):
    selinux_enforce = security_getenforce() == 1

    client = ClientMeta(dns_discovery=True)
    client.login("admin", admin_password)
    add_users(client, users, password, shell, home_prefix)
    add_groups(client, groups)
    add_users_to_groups(client, users, groups)
    client.logout()

    if enable_create_home:
        create_home(users, home_prefix, selinux_enforce, selinux_context)

    if enable_create_project:
        create_project(users, groups, project_prefix, selinux_enforce, selinux_context)

    if enable_create_scratch:
        create_scratch(users, scratch_prefix, selinux_enforce, selinux_context)

    if enable_create_home_symlinks:
        create_home_symlinks(
            users,
            groups,
            home_prefix,
            project_prefix,
            scratch_prefix,
            selinux_enforce,
            selinux_context,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a batch of users in FreeIPA")
    parser.add_argument("users", nargs="+", help="list of usernames")
    parser.add_argument(
        "--admin-password", nargs=1, default=os.environ.get("IPA_ADMIN_PASSWD")
    )
    parser.add_argument(
        "--password", nargs=1, default=os.environ.get("IPA_USER_PASSWD")
    )
    parser.add_argument("--groups", nargs="*", help="list of groups")
    parser.add_argument("--shell", default="/bin/bash")
    parser.add_argument("--chroot", default="/")
    parser.add_argument("--home-prefix", default="/home")
    parser.add_argument("--project-prefix", default="/project")
    parser.add_argument("--scratch-prefix", default="/scratch")
    parser.add_argument("--create-home", action="store_true")
    parser.add_argument("--create-project", action="store_true")
    parser.add_argument("--create-scratch", action="store_true")
    parser.add_argument("--create-home_symlinks", action="store_true")
    parser.add_argument(
        "--selinux-context", default="unconfined_u:object_r:user_home_t:s0"
    )

    args = parser.parse_args()
    main(
        args.admin_password,
        args.users,
        args.password,
        args.groups,
        args.shell,
        args.chroot,
        args.home_prefix,
        args.project_prefix,
        args.scratch_prefix,
        args.create_home,
        args.create_project,
        args.create_scratch,
        args.create_home_symlinks,
        args.selinux_context,
    )
