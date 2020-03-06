""" Utilities """
import copy
import json
import posixpath
import re
import time

try:
    from urllib.error import HTTPError
except ImportError:
    from urllib2 import HTTPError

import distlib.locators
import distlib.metadata
import logging
import six
from distlib.database import Distribution
from distlib.locators import Locator, SimpleScrapingLocator
from distlib.metadata import Metadata
from distlib.util import split_filename, urljoin, ensure_slash
from distlib.wheel import Wheel
from six.moves.urllib.parse import urlparse  # pylint: disable=F0401,E0611


# this is quite dirty, but the old implementation scraping the simple API wasn't doing any validation
# anyways (it wasn't loading data into the `Metadata` class).
# this is needed because package versions don't necessarily follow the recommended PEP version scheme and this
# was causing the version regex to fail
distlib.metadata.Metadata._validate_mapping = lambda *args, **kwargs: True


LOG = logging.getLogger(__name__)
ALL_EXTENSIONS = Locator.source_extensions + Locator.binary_extensions
SENTINEL = object()


def parse_filename(filename, name=None):
    """ Parse a name and version out of a filename """
    version = None
    for ext in ALL_EXTENSIONS:
        if filename.endswith(ext):
            if ext == ".whl":
                wheel = Wheel(filename)
                return wheel.name, wheel.version
            trimmed = filename[: -len(ext)]
            parsed = split_filename(trimmed, name)
            if parsed is None:
                break
            else:
                parsed_name, version = parsed[:2]
            break
    if version is None:
        raise ValueError("Cannot parse package file '%s'" % filename)
    if name is None:
        name = parsed_name
    return normalize_name(name), version


def normalize_name(name):
    """ Normalize a python package name """
    # Lifted directly from PEP503:
    # https://www.python.org/dev/peps/pep-0503/#id4
    return re.sub(r"[-_.]+", "-", name).lower()


class BetterScrapingLocator(SimpleScrapingLocator):

    """ Layer on top of SimpleScrapingLocator that allows preferring wheels """

    prefer_wheel = True

    def __init__(self, *args, **kw):
        kw["scheme"] = "legacy"
        super(BetterScrapingLocator, self).__init__(*args, **kw)

    def locate(self, requirement, prereleases=False, wheel=True):
        self.prefer_wheel = wheel
        return super(BetterScrapingLocator, self).locate(requirement, prereleases)

    def score_url(self, url):
        t = urlparse(url)
        filename = posixpath.basename(t.path)
        return (
            t.scheme == "https",
            not (self.prefer_wheel ^ filename.endswith(".whl")),
            "pypi.org" in t.netloc,
            filename,
        )


class EnhancedPyPIJSONLocator(Locator):
    """
    better metadata support TODO(jjekir) update docstring

    Original docstring for reference:

        This locator uses PyPI's JSON interface. It's very limited in functionality
        and probably not worth using.
    """

    prefer_wheel = True

    def __init__(self, url, **kwargs):
        kwargs["scheme"] = "legacy"
        super(EnhancedPyPIJSONLocator, self).__init__(**kwargs)
        self.base_url = ensure_slash(url)

    def locate(self, requirement, prereleases=False, wheel=True):
        self.prefer_wheel = wheel
        return super(EnhancedPyPIJSONLocator, self).locate(requirement, prereleases)

    def score_url(self, url):
        t = urlparse(url)
        filename = posixpath.basename(t.path)
        return (
            t.scheme == "https",
            not (self.prefer_wheel ^ filename.endswith(".whl")),
            "pypi.org" in t.netloc,
            filename,
        )

    def get_distribution_names(self):
        """
        Return all the distribution names known to this locator.
        """
        raise NotImplementedError('Not available from this locator')

    def _get_project(self, name):
        from distlib.locators import quote #, text_type

        result = {'urls': {}, 'digests': {}}
        url = urljoin(self.base_url, '%s/json' % quote(name))
        try:
            resp = self.opener.open(url)
            data = resp.read().decode() # for now
            d = json.loads(data)
            d['info'].update({'metadata_version': '2.0'})

            for version, infos in d['releases'].items():
                data3 = copy.deepcopy(d['info'])
                data3.update({'version': version})

                data3.pop('requires_python', None)
                if len(infos) > 0:
                    # this assumes all packages of the same version have the same requires_python metadata,
                    # which appears to be a valid assumption from a number of packages that were checked
                    data3.update({'requires_python': infos[0]['requires_python']})

                omd = Metadata(scheme=self.scheme, mapping=data3)
                odist = Distribution(omd)
                odist.locator = self
                result[version] = odist
                for info in infos:
                    url = info['url']
                    current_url = odist.metadata.source_url
                    if current_url:
                        odist.metadata.source_url = self.prefer_url(current_url, url)
                    else:
                        odist.metadata.source_url = url
                    odist.download_urls.add(url)
                    odist.digests[url] = self._get_digest(info)
                    result['urls'].setdefault(version, set()).add(url)
                    result['digests'][url] = self._get_digest(info)
        except HTTPError as e:
            if e.code != 404:
                raise
        except Exception as e:
            raise
            # self.errors.put(text_type(e))
            # logger.exception('JSON fetch failed: %s', e)
        return result


# Distlib checks if wheels are compatible before returning them.
# This is useful if you are attempting to install on the system running
# distlib, but we actually want ALL wheels so we can display them to the
# clients.  So we have to monkey patch the method. I'm sorry.
def is_compatible(wheel, tags=None):
    """ Hacked function to monkey patch into distlib """
    return True


distlib.locators.is_compatible = is_compatible


def create_matcher(queries, query_type):
    """
    Create a matcher for a list of queries

    Parameters
    ----------
    queries : list
        List of queries

    query_type: str
        Type of query to run: ["or"|"and"]

    Returns
    -------
        Matcher function

    """
    queries = [query.lower() for query in queries]
    if query_type == "or":
        return lambda x: any((q in x.lower() for q in queries))
    else:
        return lambda x: all((q in x.lower() for q in queries))


def get_settings(settings, prefix, **kwargs):
    """
    Convenience method for fetching settings

    Returns a dict; any settings that were missing from the config file will
    not be present in the returned dict (as opposed to being present with a
    None value)

    Parameters
    ----------
    settings : dict
        The settings dict
    prefix : str
        String to prefix all keys with when fetching value from settings
    **kwargs : dict
        Mapping of setting name to conversion function (e.g. str or asbool)

    """
    computed = {}
    for name, fxn in six.iteritems(kwargs):
        val = settings.get(prefix + name)
        if val is not None:
            computed[name] = fxn(val)
    return computed


class TimedCache(dict):
    """
    Dict that will store entries for a given time, then evict them

    Parameters
    ----------
    cache_time : int or None
        The amount of time to cache entries for, in seconds. 0 will not cache.
        None will cache forever.
    factory : callable, optional
        If provided, when the TimedCache is accessed and has no value, it will
        attempt to populate itself by calling this function with the key it was
        accessed with. This function should return a value to cache, or None if
        no value is found.

    """

    def __init__(self, cache_time, factory=None):
        super(TimedCache, self).__init__()
        if cache_time is not None and cache_time < 0:
            raise ValueError("cache_time cannot be negative")
        self._cache_time = cache_time
        self._factory = factory
        self._times = {}

    def _has_expired(self, key):
        """ Check if a key is both present and expired """
        if key not in self._times or self._cache_time is None:
            return False
        updated = self._times[key]
        return updated is not None and time.time() - updated > self._cache_time

    def _evict(self, key):
        """ Remove a key if it has expired """
        if self._has_expired(key):
            del self[key]

    def __contains__(self, key):
        self._evict(key)
        return super(TimedCache, self).__contains__(key)

    def __delitem__(self, key):
        del self._times[key]
        super(TimedCache, self).__delitem__(key)

    def __setitem__(self, key, value):
        if self._cache_time == 0:
            return
        self._times[key] = time.time()
        super(TimedCache, self).__setitem__(key, value)

    def __getitem__(self, key):
        self._evict(key)
        try:
            value = super(TimedCache, self).__getitem__(key)
        except KeyError:
            if self._factory:
                value = self._factory(key)
                if value is None:
                    raise
            else:
                raise
        return value

    def get(self, key, default=None):
        self._evict(key)
        value = super(TimedCache, self).get(key, SENTINEL)
        if value is SENTINEL:
            if self._factory is not None:
                value = self._factory(key)
                if value is not None:
                    self[key] = value
                    return value
                else:
                    return default
            else:
                return default
        else:
            return value

    def set_expire(self, key, value, expiration):
        """
        Set a value in the cache with a specific expiration

        Parameters
        ----------
        key : str
        value : value
        expiration : int or None
            Sets the value to expire this many seconds from now. If None, will
            never expire.

        """
        if expiration is not None:
            if expiration <= 0:
                try:
                    del self[key]
                except KeyError:
                    pass
                return
            expiration = time.time() + expiration - self._cache_time

        self._times[key] = expiration
        super(TimedCache, self).__setitem__(key, value)
