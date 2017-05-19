from setuptools import setup

setup (
    name="z3sec",
    version="0.1",
    description="Penetration testing framework to test the touchlink commissioning features of ZigBee-certified products",
    scripts=['tools/z3sec_touchlink','tools/z3sec_control','tools/z3sec_key_extract','tools/z3sec_show','tools/z3sec_install_code'],
    packages=['z3sec'],
    license="MIT",
    url="https://github.com/IoTsec/Z3sec",
)
