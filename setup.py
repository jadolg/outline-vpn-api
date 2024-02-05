# -*-coding:utf-8-*-
"""setup for outline-vpn-api"""

from setuptools import setup

setup(
    name="outline-vpn-api",
    version="5.0.0",
    packages=["outline_vpn"],
    url="https://github.com/jadolg/outline-vpn-api/",
    license="MIT",
    author="Jorge Alberto Díaz Orozco (Akiel)",
    author_email="diazorozcoj@gmail.com",
    description="Python API wrapper for Outline VPN",
    long_description=open("README.md", "r").read(),  # pylint: disable=R1732
    long_description_content_type="text/markdown",
    install_requires=("requests",),
)
