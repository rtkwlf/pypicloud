""" Views for simple api calls that return json data """
import posixpath

import logging
import six
from contextlib import closing

# pylint: disable=E0611,W0403
from paste.httpheaders import CONTENT_DISPOSITION, CACHE_CONTROL

# pylint: enable=E0611,W0403
from pyramid.httpexceptions import HTTPNotFound, HTTPForbidden, HTTPBadRequest
from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.view import view_config
from pyramid_duh import argify, addslash
from six.moves.urllib.request import urlopen  # pylint: disable=F0401,E0611

from .login import handle_register_request
from pypicloud.route import (
    APIResource,
    APIPackageResource,
    APIPackagingResource,
    APIPackageFileResource,
)
from pypicloud.util import normalize_name


LOG = logging.getLogger(__name__)


@view_config(
    context=APIPackagingResource, request_method="GET", subpath=(), renderer="json"
)
@addslash
@argify
def all_packages(request, verbose=False):
    """ List all packages """
    if verbose:
        packages = request.db.summary()
    else:
        packages = request.db.distinct()
    i = 0
    while i < len(packages):
        package = packages[i]
        name = package if isinstance(package, six.string_types) else package["name"]
        if not request.access.has_permission(name, "read"):
            del packages[i]
            continue
        i += 1
    return {"packages": packages}


@view_config(
    context=APIPackageResource,
    request_method="GET",
    subpath=(),
    renderer="json",
    permission="read",
)
@addslash
def package_versions(context, request):
    """ List all unique package versions """
    normalized_name = normalize_name(context.name)
    versions = request.db.all(normalized_name)
    return {
        "packages": versions,
        "write": request.access.has_permission(normalized_name, "write"),
    }


def fetch_and_cache_dist(request, package_name, package_url, package_metadata):
    """ Fetch a Distribution and upload it to the storage backend """
    filename = posixpath.basename(package_url)
    url = urlopen(package_url)
    with closing(url):
        data = url.read()
    # TODO: digest validation
    return (
        request.db.upload(filename, six.BytesIO(data), name=package_name, metadata=package_metadata),
        data
    )


@view_config(context=APIPackageFileResource, request_method="GET", permission="read")
def download_package(context, request):
    """ Download package, or redirect to the download link """
    package = request.db.fetch(context.filename)
    if not package:
        if request.registry.fallback != "cache":
            return HTTPNotFound()
        if not request.access.can_update_cache():
            return request.forbid()
        # If we are caching pypi, download the package from pypi and save it
        dists = request.locator.get_project(context.name)

        dist = None
        source_url = None
        for version, url_set in six.iteritems(dists.get("urls", {})):
            if dist is not None:
                break
            for url in url_set:
                if posixpath.basename(url) == context.filename:
                    source_url = url
                    dist = dists[version]
                    break
        if dist is None:
            return HTTPNotFound()
        LOG.info("Caching %s from %s", context.filename, request.fallback_simple)

        # we only cache the requires_python field
        metadata = {
            'requires_python' : dist.metadata.dictionary.get('requires_python')
        }
        package, data = fetch_and_cache_dist(request, dist.name, source_url, package_metadata=metadata)
        disp = CONTENT_DISPOSITION.tuples(filename=package.filename)
        request.response.headers.update(disp)
        cache_control = CACHE_CONTROL.tuples(
            public=True, max_age=request.registry.package_max_age
        )
        request.response.headers.update(cache_control)
        request.response.body = data
        request.response.content_type = "application/octet-stream"
        return request.response
    if request.registry.stream_files:
        with request.db.storage.open(package) as data:
            request.response.body = data.read()
        disp = CONTENT_DISPOSITION.tuples(filename=package.filename)
        request.response.headers.update(disp)
        cache = CACHE_CONTROL.tuples(
            public=True, max_age=request.registry.package_max_age
        )
        request.response.headers.update(cache)
        request.response.content_type = "application/octect-stream"
        return request.response
    response = request.db.download_response(package)
    return response


@view_config(
    context=APIPackageFileResource,
    request_method="POST",
    subpath=(),
    renderer="json",
    permission="write",
)
@argify
def upload_package(context, request, content):
    """ Upload a package """
    # TODO: fix in future to support metadata? more work than just this place. should be
    # unnecessary for now since we are dual py2/py3 support and there are other ways for us
    # to control our own packages
    try:
        return request.db.upload(content.filename, content.file, name=context.name)
    except ValueError as e:  # pragma: no cover
        return HTTPBadRequest(*e.args)


@view_config(
    context=APIPackageFileResource,
    request_method="DELETE",
    subpath=(),
    permission="write",
)
def delete_package(context, request):
    """ Delete a package """
    package = request.db.fetch(context.filename)
    if package is None:
        return HTTPBadRequest("Could not find %s" % context.filename)
    request.db.delete(package)
    return request.response


@view_config(
    context=APIResource,
    name="user",
    request_method="PUT",
    subpath=("username/*"),
    renderer="json",
    permission=NO_PERMISSION_REQUIRED,
)
@argify
def register(request, password):
    """ Register a user """
    username = request.named_subpaths["username"]
    return handle_register_request(request, username, password)


@view_config(
    context=APIResource,
    name="user",
    subpath=("password"),
    request_method="POST",
    permission="login",
)
@argify
def change_password(request, old_password, new_password):
    """ Change a user's password """
    if not request.access.verify_user(request.userid, old_password):
        return HTTPForbidden()
    request.access.edit_user_password(request.userid, new_password)
    return request.response


@view_config(
    context=APIResource,
    name="fetch",
    renderer="json",
    permission=NO_PERMISSION_REQUIRED,
)
@argify(wheel=bool, prerelease=bool)
def fetch_requirements(request, requirements, wheel=True, prerelease=False):
    """
    Fetch packages from the fallback_base_url

    Parameters
    ----------
    requirements : str
        Requirements in the requirements.txt format (with newlines)
    wheel : bool, optional
        If True, will prefer wheels (default True)
    prerelease : bool, optional
        If True, will allow prerelease versions (default False)

    Returns
    -------
    pkgs : list
        List of Package objects

    """
    if not request.access.can_update_cache():
        return HTTPForbidden()
    packages = []
    # pep 508 doesn't seem to be fully implemented in distlib, i.e. `; python_version < "2.7"` probably
    # doesn't work using the default locator
    for line in requirements.splitlines():
        dist = request.locator.locate(line, prerelease, wheel)
        if dist is not None:
            try:
                metadata = dict(requires_python=dist.metadata.dictionary.get('requires_python'))
                packages.append(fetch_and_cache_dist(request, dist.name, dist.source_url, metadata)[0])
            except ValueError:
                pass
    return {"pkgs": packages}
