#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from operator import itemgetter
import urllib

import click
import dateutil.parser
import pyalpm
import pycman.pkginfo
import requests
import sys

# monkeypatch pycman
pycman.pkginfo.ATTRNAME_FORMAT = '%-13s : '
pycman.pkginfo.ATTR_INDENT = 16 * ' '


class SignoffSession:
    """
    Helper class for talking to ArchWeb.
    """

    def __init__(self,
                 username,
                 password,
                 base_url="https://www.archlinux.org/"):
        self.base_url = base_url
        self.username = username
        self.session = requests.Session()
        self._login(username, password)

    def _login(self, username, password):
        # get CSRF token
        self.session.get(self._login_url())
        csrftoken = self.session.cookies["csrftoken"]

        # login
        response = self.session.post(
            self._login_url(),
            data={
                "username": username,
                "password": password,
                "csrfmiddlewaretoken": csrftoken
            },
            headers={"referer": self._login_url()},
            allow_redirects=False)

        if not 300 <= response.status_code < 400:
            raise click.BadParameter("could not log in -- check credentials")

    def logout(self):
        """
        Log out of Archweb.
        """
        self.session.get(self._logout_url())

    def get_signoffs(self):
        """
        Fetch signoff packages.
        """
        response = self.session.get(self._signoffs_url())
        response_json = response.json()
        assert response_json["version"] == 2

        return response_json["signoff_groups"]

    def signoff_package(self, package):
        """
        Signoff a package.
        """
        self.session.get(self._signoff_url(package)).raise_for_status()

    def revoke_package(self, package):
        """
        Revoke a package signoff.
        """
        self.session.get(self._revoke_url(package)).raise_for_status()

    def _login_url(self):
        return urllib.parse.urljoin(self.base_url, "/login/")

    def _logout_url(self):
        return urllib.parse.urljoin(self.base_url, "/logout/")

    def _signoffs_url(self):
        return urllib.parse.urljoin(self.base_url, "/packages/signoffs/json/")

    def _signoff_url(self, package):
        return urllib.parse.urljoin(
            self.base_url,
            "/packages/{repo}/{arch}/{pkgbase}/signoff/".format(**package))

    def _revoke_url(self, package):
        return urllib.parse.urljoin(self._signoff_url(package), "revoke/")


def signoff_status(package, user):
    """
    Return the current sign-off status of package and user. Returns either
    "signed-off", "revoked", or None.
    """
    # sort by latest signoffs first
    signoffs = sorted(
        package["signoffs"],
        key=lambda s: dateutil.parser.parse(s["created"]),
        reverse=True)

    for signoff in signoffs:
        # skip until we find a signoff by the specified user
        if signoff["user"] != user:
            continue

        return "revoked" if signoff["revoked"] else "signed-off"
    else:
        return None


def list_signoffs(signoff_session, alpm_handle):
    """
    Generator for (signoff_pkg, local_pkg) tuples, sorted by pkgbase.
    """
    signoffs = signoff_session.get_signoffs()

    for signoff_package in sorted(signoffs, key=itemgetter("pkgbase")):
        pkgbase = signoff_package["pkgbase"]
        search = alpm_handle.get_localdb().search(pkgbase)
        local = filter(lambda pkg: pkgbase == (pkg.base or pkg.name), search)
        local_package = next(local, None)

        yield (signoff_package, local_package)


def filter_signoffs(signoffs, options):
    """
    Filter a sequence of (signoff_package, local_package) tuples with respect
    to the given options.
    """
    for signoff_package, local_package in signoffs:
        # command-line packages override other filters
        if options.packages:
            if signoff_package["pkgbase"] in options.packages:
                yield (signoff_package, local_package)
            continue

        # check signoff status
        signed_off = signoff_status(signoff_package,
                                    options.username) == "signed-off"
        if signed_off and not options.show_signed_off:
            continue

        # check install stauts
        if local_package is None and not options.show_uninstalled:
            continue

        yield (signoff_package, local_package)


def format_signoff_user(signoff):
    """
    Format a single user signoff dictionary. Return "<username>" if signoff is
    valid, and "<username> (revoked)" if the signoff is revoked.
    """
    if signoff["revoked"]:
        return signoff["user"] + " (revoked)"
    else:
        return signoff["user"]


def format_attr(*args, **kwargs):
    """
    Format an attribute in pacman -Qi style.
    """
    formatted = pycman.pkginfo.format_attr(*args, **kwargs)
    index = formatted.index(":") + 1
    return click.style(formatted[:index], bold=True) + formatted[index:]


def format_signoff(signoff_pkg, local_pkg, options):
    """
    Format a signoff package dictionary and optional local package.
    """
    if options.quiet:
        return format_signoff_short(signoff_pkg, local_pkg, options)
    else:
        return format_signoff_long(signoff_pkg, local_pkg, options)


def format_signoff_short(signoff_pkg, local_pkg, options):
    """
    Format a signoff package in a one-line style.
    """
    formatted = "{name} {version}".format(
        name=click.style(signoff_pkg["pkgbase"], bold=True),
        version=click.style(signoff_pkg["version"], bold=True, fg="green"))

    # show outdated or installed indicator if appropriate
    if local_pkg is not None and local_pkg.version != signoff_pkg["version"]:
        formatted += click.style(" (outdated)", bold=True, fg="red")
    elif options.show_uninstalled and local_pkg:
        formatted += click.style(" (installed)", bold=True, fg="blue")

    # show known bad indicator
    if signoff_pkg["known_bad"]:
        formatted += click.style(" (known bad)", bold=True, fg="red")

    # show signed-off indicator if we're listing signed off packages
    status = signoff_status(signoff_pkg, options.username)
    if options.show_signed_off and status == "signed-off":
        formatted += click.style(" [signed off]", bold=True, fg="cyan")
    elif status == "revoked":
        formatted += click.style(" [revoked]", bold=True, fg="red")

    return formatted


def format_signoff_long(signoff_pkg, local_pkg, options):
    """
    Format a signoff package in pacman -Qi style.
    """
    attributes = []

    # package base/name as appropriate
    if len(signoff_pkg["pkgnames"]) > 1:
        attributes.append(format_attr("Package base", signoff_pkg["pkgbase"]))
        attributes.append(format_attr("Packages", signoff_pkg["pkgnames"]))
    else:
        attributes.append(format_attr("Package", signoff_pkg["pkgbase"]))

    # version, including local version if they differ
    attributes.append(format_attr("Version", signoff_pkg["version"]))
    if local_pkg:
        if local_pkg.version != signoff_pkg["version"]:
            attributes.append(format_attr("Local version", local_pkg.version))

    # last update, and install date if package is installed
    last_update = dateutil.parser.parse(signoff_pkg["last_update"]).timestamp()
    attributes.append(format_attr("Last updated", last_update, format_str="time"))
    if local_pkg:
        attributes.append(
            format_attr("Install date", local_pkg.installdate, format_str="time"))

    # packager and comments
    attributes.append(format_attr("Packager", signoff_pkg["packager"]))
    attributes.append(
        format_attr("Comments", signoff_pkg["comments"] or "None"))

    # signoffs
    signoffs = [
        format_signoff_user(signoff) for signoff in signoff_pkg["signoffs"]
    ]
    attributes.append(format_attr("Signoffs", signoffs))

    # current user signoff status
    status = signoff_status(signoff_pkg, options.username)
    if status is None:
        signed_off = "No"
    elif status == "signed-off":
        signed_off = "Yes"
    elif status == "revoked":
        signed_off = "Revoked"
    attributes.append(format_attr("Signed off", signed_off))

    # bad status
    if signoff_pkg["known_bad"]:
        attributes.append(format_attr("Known bad", "Yes"))

    return "\n".join(attributes)


def warn_if_outdated(signoff_pkg, local_pkg):
    """
    Echo a warning message if local and sign-off package versions differ.
    """
    if local_pkg.version != signoff_pkg["version"]:
        click.echo(
            click.style("warning:", fg="yellow", bold=True) + " local "
            "{pkg} ({local_version}) is not the same as sign-off version "
            "({signoff_version})".format(
                pkg=signoff_pkg["pkgbase"],
                local_version=local_pkg.version,
                signoff_version=signoff_pkg["version"]))


def warn_if_bad(signoff_pkg):
    """
    Echo a warning message if sign-off package is bad.
    """
    if signoff_pkg["known_bad"]:
        click.echo(
            click.style("warning:", fg="yellow", bold=True) +
            " {pkg} is known to be bad".format(
                pkg=signoff_pkg["pkgbase"]))


def confirm(text, *args, **kwargs):
    """
    Wrapper around click.confirm that adds minor styling to the prompt.
    """
    prefix = click.style(":: ", bold=True, fg="blue")
    styled = click.style(text, bold=True)
    return click.confirm(prefix + styled, *args, **kwargs)


class Options:
    """
    Simple helper class for holding arbitrary command-line options.
    """

    def __init__(self, **kwargs):
        for kwarg in kwargs:
            setattr(self, kwarg, kwargs[kwarg])


@click.command(context_settings={"help_option_names": ("-h", "--help")})
@click.option("-s", "--signoff", "action", flag_value="signoff", help="sign "
              "off packages")
@click.option("-r", "--revoke", "action", flag_value="revoke", help="revoke "
              "signed-off packages")
@click.option("-l", "--list", "action", flag_value="list", help="list "
              "packages that can be signed off")
@click.option("-i", "--interactive", "action", flag_value="interactive",
              help="interactively sign off packages")
@click.option("-u", "--uninstalled", is_flag=True, help="include uninstalled "
              "packages when listing")
@click.option("-a", "--signed-off", is_flag=True, help="include signed-off "
              "packages when listing")
@click.option("-q", "--quiet", is_flag=True, help="be less verbose when "
              "listing packages")
@click.option("--username", prompt=True, envvar="ARCHWEB_USERNAME",
              help="ArchWeb username (ARCHWEB_USERNAME env. var.)")
@click.option("--password", prompt=True, hide_input=True,
              envvar="ARCHWEB_PASSWORD", help="ArchWeb password (ARCHWEB_PASSWORD "
              "env. var.)")
@click.option("-b", "--db-path", type=click.Path(), default="/var/lib/pacman",
              help="pacman database path")
@click.option("--noconfirm", is_flag=True, help="don't ask for confirmation")
@click.argument("package", nargs=-1)
def main(action, uninstalled, signed_off, quiet, username, password, package,
         db_path, noconfirm):
    """
    Interface with Arch Linux package signoffs.
    """
    if action is None:
        if package:
            action = "signoff"
        else:
            action = "list"

    options = Options(
        action=action,
        show_uninstalled=uninstalled,
        show_signed_off=signed_off,
        quiet=quiet,
        packages=set(package),
        db_path=db_path,
        username=username,
        noconfirm=noconfirm)

    # initialize alpm handle and signoff session
    try:
        alpm_handle = pyalpm.Handle("/", options.db_path)
    except pyalpm.error:
        click.echo("error: could not read alpm database {}".format(options.db_path),
                   err=True)
        sys.exit(1)

    session = SignoffSession(options.username, password)

    # fetch and filter signoff packages
    signoffs = list(list_signoffs(session, alpm_handle))
    packages = list(filter_signoffs(signoffs, options))
    pkgbases = set(signoff_pkg["pkgbase"] for signoff_pkg, _ in packages)

    # if packages are supplied as parameters, validate them
    for pkgbase in options.packages:
        if pkgbase not in pkgbases:
            raise click.BadParameter(
                "package base {} not found in signoffs".format(pkgbase))

    if action == "list":  # output packages and exit
        for signoff_pkg, local_pkg in packages:
            click.echo(format_signoff(signoff_pkg, local_pkg, options))
            if not options.quiet:
                click.echo()  # add a line between packages
    elif action == "signoff":  # sign-off packages
        for signoff_pkg, local_pkg in packages:
            warn_if_outdated(signoff_pkg, local_pkg)
            warn_if_bad(signoff_pkg)
        if options.noconfirm or confirm("Sign off {}?".format(
                click.style(" ".join(pkgbases), bold=True))):
            for signoff_pkg, local_pkg in packages:
                try:
                    session.signoff_package(signoff_pkg)
                except requests.exceptions.HTTPError as e:
                    click.echo("Could not sign off {} ({})".format(signoff_pkg["pkgbase"], e))
                else:
                    click.echo("Signed off {}.".format(signoff_pkg["pkgbase"]))
    elif action == "revoke":  # revoke sign-offs
        for signoff_pkg, local_pkg in packages:
            warn_if_outdated(signoff_pkg, local_pkg)
            warn_if_bad(signoff_pkg)
        if options.noconfirm or confirm("Revoke sign-off for {}?".format(
                click.style(" ".join(pkgbases), bold=True))):
            for signoff_pkg, local_pkg in packages:
                session.revoke_package(signoff_pkg)
                click.echo("Revoked sign-off for {}.".format(
                    signoff_pkg["pkgbase"]))
    elif action == "interactive":  # interactively sign-off or revoke
        for signoff_pkg, local_pkg in packages:
            click.echo(format_signoff(signoff_pkg, local_pkg, options))
            warn_if_outdated(signoff_pkg, local_pkg)
            warn_if_bad(signoff_pkg)
            if not options.quiet:
                click.echo()

            # check if we're signing off or revoking
            pkgbase = signoff_pkg["pkgbase"]
            signed_off = signoff_status(signoff_pkg,
                                        options.username) == "signed-off"

            if signed_off:
                prompt = "Revoke sign-off for {}?".format(pkgbase)
            else:
                prompt = "Sign off {}?".format(pkgbase)

            # confirm and signoff/revoke
            if confirm(prompt):
                if signed_off:
                    session.revoke_package(signoff_pkg)
                    click.echo("Revoked sign-off for {}.".format(pkgbase))
                else:
                    session.signoff_package(signoff_pkg)
                    click.echo("Signed off {}.".format(pkgbase))

            click.echo()

    session.logout()


if __name__ == "__main__":
    main()
