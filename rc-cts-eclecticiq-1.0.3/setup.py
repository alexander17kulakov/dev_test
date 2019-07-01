from __future__ import print_function

from setuptools import setup, find_packages

setup(
    name='rc-cts-eclecticiq',
    version='1.0.3',
    url='https://www.eclecticiq.com',
    license='MIT',
    author='EclecticIQ',
    author_email='support@eclecticiq.com',
    install_requires=[
        'rc-cts'
    ],
    description="Resilient Circuits Custom Threat Service for EclecticIQ platform",
    long_description="Resilient Circuits Custom Threat Service for EclecticIQ platform",
    packages=find_packages(),
    include_package_data=True,
    platforms='any',
    classifiers=[
        'Programming Language :: Python',
    ],
    entry_points={
        # Register the component with resilient_circuits
        "resilient.circuits.components": [
            "EclecticIQLookup = rc_cts_eclecticiq.components.searcher:EclecticIQLookup"
        ],
        "resilient.circuits.configsection": ["gen_config = rc_cts_eclecticiq.util.config:config_section_data"],
    }
)
