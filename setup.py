# -*- coding: utf-8 -*-


from setuptools import setup, find_packages, Extension

from codecs import open
from os.path import abspath


pkg_name = "mood.sockets"
pkg_version = "2.0.0"
pkg_desc = "mood sockets module"

PKG_VERSION = ("PKG_VERSION", "\"{0}\"".format(pkg_version))


setup(
    name=pkg_name,
    version=pkg_version,
    description=pkg_desc,
    long_description=open(abspath("README.txt"), encoding="utf-8").read(),
    long_description_content_type="text",

    url="https://github.com/lekma/mood.sockets",
    download_url="https://github.com/lekma/mood.sockets/releases",
    project_urls={
        "Bug Tracker": "https://github.com/lekma/mood.sockets/issues"
    },
    author="Malek Hadj-Ali",
    author_email="lekmalek@gmail.com",
    license="The Unlicense (Unlicense)",
    platforms=["Linux"],
    keywords="linux sockets",

    setup_requires = ["setuptools>=24.2.0"],
    python_requires="~=3.10",
    packages=find_packages(),
    namespace_packages=["mood"],
    zip_safe=False,

    ext_package="mood",
    ext_modules=[
        Extension(
            "sockets",
            [
                "src/helpers/helpers.c",
                "src/sockets.c"
            ],
            define_macros=[PKG_VERSION]
        )
    ],

    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: The Unlicense (Unlicense)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: Implementation :: CPython"
    ]
)
