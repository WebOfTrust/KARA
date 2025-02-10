#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
$ python setup.py register sdist upload

First Time register project on pypi
https://pypi.org/manage/projects/


Pypi Release
$ pip3 install twine

$ python3 setup.py sdist
$ twine upload dist/keri-0.0.1.tar.gz

Create release git:
$ git tag -a v0.4.2 -m "bump version"
$ git push --tags
$ git checkout -b release_0.4.2
$ git push --set-upstream origin release_0.4.2
$ git checkout master

Best practices for setup.py and requirements.txt
https://caremad.io/posts/2013/07/setup-vs-requirement/
"""

from glob import glob
from os.path import basename
from os.path import splitext
from pathlib import Path

from setuptools import find_packages, setup

this_directory = Path(__file__).parent
if (this_directory / "README.md").exists():  # If building inside a container this file won't exist and fails the build
    long_description = (this_directory / "README.md").read_text()
else:
    long_description = "KERI auditing server that responds to credential presentations by signaling via webhooks."

setup(
    name='kara',
    version='0.0.2',  # also change in src/kara/__init__.py
    license='Apache Software License 2.0',
    description='KERI Audit Reporting Agent',
    long_description=long_description,
    author='Philip S. Feairheller',
    author_email='pfeairheller@gmail.com',
    url='https://github.com/WebOfTrust/kara',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=[splitext(basename(path))[0] for path in glob('src/*.py')],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        # complete classifier list: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: Unix',
        'Operating System :: POSIX',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: Implementation :: CPython',
        # uncomment if you test on these interpreters:
        # 'Programming Language :: Python :: Implementation :: PyPy',
        # 'Programming Language :: Python :: Implementation :: IronPython',
        # 'Programming Language :: Python :: Implementation :: Jython',
        # 'Programming Language :: Python :: Implementation :: Stackless',
        'Topic :: Utilities',
    ],
    project_urls={
        'Source': 'https://github.com/WebOfTrust/kara',
        'Documentation': 'https://kara.readthedocs.io/',
        'Changelog': 'https://kara.readthedocs.io/en/latest/changelog.html',
        'Issue Tracker': 'https://github.com/WebOfTrust/kara/issues',
    },
    keywords=[
        'KERI', 'ACDC', 'reporting agent', 'decentralized identity'
    ],
    python_requires='>=3.12.2',
    install_requires=[
        'keri==1.2.4',
        'hio==0.6.14',
        'multicommand==1.0.0',
        'blake3==0.4.1',
        'falcon==4.0.2',
        'http_sfv>=0.9.9'
    ],
    extras_require={
        'test': ['pytest', 'coverage', 'pytest-mock-server'],
        'docs': ['sphinx', 'sphinx-rtd-theme']
    },
    tests_require=[
        'coverage>=7.6.10',
        'pytest>=8.3.4',
        'pytest-mock-server>=0.3.2'
    ],
    setup_requires=[
        'setuptools==75.8.0'
    ],
    entry_points={
        'console_scripts': [
            'kara = kara.app.cli.kli:main',
        ]
    },
)
