#!/usr/bin/env python3
"""
Download metadata for a Fedora repository in order to show a dependency tree for
packages, display checksums and optionally download the required files.
"""
import argparse
import gzip
import hashlib
import logging
import os
import re
import shutil
import sys
import time
import requests
from lxml import etree

_logger = logging.getLogger(__name__)


class ProgressBar:
    def __init__(self, size):
        self.size = size
        self.offset = 0
        self.lastupdate = time.time()
        self.printed = False

    def _report_progress(self, eol):
        cols, _ = shutil.get_terminal_size()
        if cols < 50:
            return  # don't show a progress bar on such a small output.
        perc = max(0, min(1, self.offset / self.size))
        barwidth = cols - 30
        bar = (int((barwidth - 1) * perc) * '=' + '>').ljust(barwidth)
        print('\r%3d%%[%s] %s' % (100 * perc, bar, self.size_str()), end=eol)

    def size_str(self):
        sz = self.offset
        if sz >= 1024**3:
            return '%.2fG' % (sz / 1024**3)
        elif sz >= 1024**2:
            return '%.2fM' % (sz / 1024**2)
        elif sz >= 1024**1:
            return '%.2fK' % (sz / 1024**1)
        else:
            return '%dB' % sz

    def update(self, chunk_size):
        self.offset += chunk_size
        now = time.time()
        if self.size and now - self.lastupdate >= 0.3:
            self.lastupdate = now
            self._report_progress(eol=' ')
            self.printed = True

    def finish(self):
        if self.printed:
            self._report_progress(eol='\n')


class PackageInfo:
    def __init__(self, name, arch, version, sha256, size, location, provides, requires):
        self.name = name
        self.arch = arch
        self.version = version
        self.sha256 = sha256
        self.size = size
        self.location = location
        self.provides = provides
        self.requires = requires
        self.url = None

    def __str__(self):
        return self.name

    def __repr__(self):
        return repr(self.name)

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        return self.name == other.name

    def __lt__(self, other):
        return self.name < other.name


def is_interesting_name(name):
    return name.startswith('mingw')


def parse_checksum(node):
    value = node.findtext('{*}checksum[@type="sha256"]')
    if not re.match('^[0-9a-f]{40}', value):
        raise RuntimeError('Invalid checksum: %s' % value)
    return value


def parse_location(node, expected_suffix=None):
    path = node.find('{*}location').get('href')
    if not re.match(r'^(?:[a-z]+/)+(?:[0-9a-z_+-]+\.)+[a-z]+$', path, flags=re.I):
        raise RuntimeError('Forbidden path: %s' % path)
    if expected_suffix and not path.endswith(expected_suffix):
        raise RuntimeError('Unexpected suffix for path: %s' % path)
    return path


def parse_entry_names(package, name):
    el = package.find('.//{*}%s' % name)
    if el is None:
        return
    for entry in el.iterfind('{*}entry'):
        name = entry.get('name')
        if is_interesting_name(name):
            yield name


def parse_version(el):
    # <version epoch="0" ver="1.5.3" rel="2.fc29"/>
    # Packages/p/pkgconf-pkg-config-1.5.3-2.fc29.i686.rpm
    return '%s-%s' % (el.get('ver'), el.get('rel'))


def parse_packages(filename):
    with gzip.open(filename) as xmlf:
        packages_iter = etree.iterparse(xmlf, tag='{*}package')
        for _, package in packages_iter:
            name = package.findtext('{*}name')
            arch = package.findtext('{*}arch')
            # noaarch for normal packages, x86_64 for mingw64-pkg-config
            if not is_interesting_name(name) or arch not in ('x86_64', 'noarch'):
                package.clear()
                continue
            pkg = PackageInfo(
                name,
                arch,
                parse_version(package.find('{*}version')),
                parse_checksum(package),
                int(package.find('{*}size').get('package')),
                parse_location(package, '.rpm'),
                list(parse_entry_names(package, 'provides')),
                list(parse_entry_names(package, 'requires')),
            )
            package.clear()
            yield pkg


class PackageIndex:
    def __init__(self):
        # map: name -> PackageInfo
        self.all_packages = {}
        # map: alias -> set(PackageInfo)
        self.provides = None

    def load_from_primary(self, filename, base_url):
        '''Load extra packages from the given index file.'''
        all_packages = {}
        # Load all packages
        for pkg in parse_packages(filename):
            if pkg.name in all_packages:
                _logger.warning('duplicate package in %s: %s',
                                filename, pkg.name)
            pkg.url = base_url + pkg.location
            all_packages[pkg.name] = pkg
        self.all_packages.update(all_packages)

    def finish(self):
        '''Resolve dependencies for the currently known packages.'''
        provides = {}
        for pkg in self.all_packages.values():
            for alias in pkg.provides:
                provides.setdefault(alias, set()).add(pkg)
        # Convert set to a list
        provides = {alias: sorted(ps) for alias, ps in provides.items()}

        # Verify dependencies
        for pkg in self.all_packages.values():
            for alias in pkg.requires:
                others = provides.get(alias)
                if not others:
                    _logger.warning('package %s requires %s which is not found',
                                    pkg.name, alias)
                elif len(others) != 1:
                    _logger.warning('package %s requires %s, found multiple: %s',
                                    pkg.name, alias, others)
        self.provides = provides

    def walk_depends(self, names, ignore=(), action=None, pkg_action=None):
        '''
        Walk through the dependencies of packages in 'names', ignoring packages
        that occur in 'ignore'. Calls either 'action' to walk the dependency
        tree or 'pkg_action' (which receives a unique PackageInfo object).
        '''
        assert (action is None) ^ (
            pkg_action is None), 'One callback is required'
        # Each item: name, level, isFirst. Last item is printed first.
        queue = []
        seen = set()

        def add_depends(names, level):
            items = []
            for name in names:
                pkg = self.provides[name][0]
                items.append((name, level, pkg.name not in seen))
                seen.add(pkg.name)
            queue.extend(items[::-1])
        add_depends(names, 0)
        while queue:
            name, level, isFirst = queue.pop()
            pkg = self.provides[name][0]
            if pkg.name in ignore:
                continue
            if pkg_action is not None and isFirst:
                pkg_action(pkg)
            elif action is not None:
                action(pkg, name, level, isFirst)
            if isFirst:
                add_depends(pkg.requires, level + 1)


def print_depends(pkg, name, level, isFirst):
    line = '%s+ %s' % (level * '  ', pkg.name)
    if pkg.name != name:
        line += ' (%s)' % name
    if isFirst:
        line = '%-64s %s.%s' % (line, pkg.version, pkg.arch)
    print(line)


def print_url(pkg):
    print(pkg.url)


def print_checksum(pkg):
    print('%s  %s' % (pkg.sha256, pkg.location.split('/')[-1]))


def download(session, destdir, url, size=None, sha256=None):
    filename = url.split('/')[-1]
    output_filename = os.path.join(destdir, filename)
    h = hashlib.sha256()
    dl_offset = 0
    # If file exists, but is truncated, try to resume downloading.
    if os.path.exists(output_filename):
        with open(output_filename, 'rb') as f:
            while True:
                data = f.read(1024**2)
                if not data:
                    break
                dl_offset += len(data)
                h.update(data)
    if dl_offset and (size is None or dl_offset == size):
        print('Using cached file %s' % filename)
    else:
        print('Downloading file %s (%s bytes)' % (filename, size or '?'))
        pbar = ProgressBar(size)
        headers = {'Range': 'bytes=%d-' % dl_offset} if dl_offset else {}
        r = session.get(url, headers=headers, stream=True)
        r.raise_for_status()
        if dl_offset and r.status_code != 206:
            # Range request not supported? Too bad, do a full transfer.
            dl_offset = 0
            h = hashlib.sha256()
        else:
            pbar.update(dl_offset)
        with open(output_filename, 'ab' if dl_offset else 'wb') as f:
            for data in r.iter_content(chunk_size=1024**2):
                pbar.update(len(data))
                f.write(data)
                h.update(data)
        pbar.finish()
    if sha256:
        actual_sha256 = h.hexdigest()
        if sha256 != actual_sha256:
            raise RuntimeError('Corrupted file %s: expected %s got %s' %
                               (filename, sha256, actual_sha256))
    return output_filename


def fetch_repo_info(mirror, url_prefix, cache_dir):
    '''Fetch and check repository metadata. Returns path to primary xml file.'''
    with requests.Session() as s:
        repomd_urlpath = url_prefix + 'repodata/repomd.xml'
        repomd_dest = os.path.join(cache_dir, os.path.dirname(repomd_urlpath))
        os.makedirs(repomd_dest, exist_ok=True)
        repomd_path = download(s, repomd_dest, mirror + repomd_urlpath)
        with open(repomd_path, 'rb') as f:
            repomd = etree.parse(f)
            entry = repomd.find('{*}data[@type="primary"]')
            pxml_sha256 = parse_checksum(entry)
            pxml_size = int(entry.findtext('{*}size'))
            pxml_location = parse_location(entry, '-primary.xml.gz')
        pxml_urlpath = url_prefix + pxml_location
        pxml_dest = os.path.join(cache_dir, os.path.dirname(pxml_urlpath))
        os.makedirs(pxml_dest, exist_ok=True)
        pxml_path = download(s, pxml_dest, mirror + pxml_urlpath,
                             size=pxml_size, sha256=pxml_sha256)
        return pxml_path


default_ignore_packages = ['mingw32-filesystem', 'mingw64-filesystem']
default_mirror = 'https://mirror.nl.leaseweb.net/fedora/linux'

parser = argparse.ArgumentParser()
parser.add_argument('--cachedir', default='/tmp/fedora-repo-cache',
                    help='Cache directory for repository metadata (default %(default)s)')
parser.add_argument('--release', default='29',
                    help='Fedora release (default %(default)s)')
parser.add_argument('--ignore', action='append', default=[],
                    help='Extra packages to ignore (mingw64- and mingw32- will be prepended)')
parser.add_argument('--mirror', default=default_mirror,
                    help='Mirror URL (default %(default)s)')
parser.add_argument('--download', action='store_true',
                    help='Download RPM files')
parser.add_argument('packages', nargs='+', help='package name')


def main():
    args = parser.parse_args()
    cachedir = args.cachedir
    mirror = '%s/' % args.mirror.rstrip('/')
    prefixes = []
    if args.release == 'rawhide':
        prefixes.append('development/rawhide/Everything/x86_64/os/')
    else:
        prefixes.append('releases/%d/Everything/x86_64/os/' %
                        int(args.release))
        prefixes.append('updates/%d/Everything/x86_64/' % int(args.release))
    ignore_packages = default_ignore_packages
    ignore_packages += ['mingw64-%s' % name for name in args.ignore]
    ignore_packages += ['mingw32-%s' % name for name in args.ignore]
    ignore_packages += args.ignore
    packages = args.packages

    # Load package info
    pi = PackageIndex()
    for prefix in prefixes:
        primary_xml_filename = fetch_repo_info(mirror, prefix, cachedir)
        pi.load_from_primary(primary_xml_filename, mirror + prefix)
    pi.finish()

    bad = False
    for pkgname in packages:
        if not pkgname in pi.provides:
            _logger.error('Requested package not found: %s', pkgname)
            bad = True
    if bad:
        return 1

    pi.walk_depends(packages, ignore=ignore_packages, action=print_depends)
    print()
    pi.walk_depends(packages, ignore=ignore_packages,
                    pkg_action=lambda pkg: print_url(pkg))
    print()
    pi.walk_depends(packages, ignore=ignore_packages,
                    pkg_action=print_checksum)

    if args.download:
        def download_pkg(pkg):
            download(s, '.', pkg.url,
                     size=pkg.size, sha256=pkg.sha256)
        with requests.Session() as s:
            pi.walk_depends(packages, ignore=ignore_packages,
                            pkg_action=download_pkg)


if __name__ == '__main__':
    sys.exit(main())
