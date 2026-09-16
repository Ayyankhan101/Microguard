import pathlib
import re

from setuptools import find_packages, setup

# Read the version from the package rather than restating it. These drifted:
# setup.py said 2.0.0 while microguard/__init__.py said 3.0.0, so a wheel
# reported a version four majors behind what the code called itself. Parsed
# with a regex instead of imported so setup.py never needs the dependencies.
_INIT = pathlib.Path(__file__).parent / "microguard" / "__init__.py"
_VERSION = re.search(
    r'^__version__ = "([^"]+)"', _INIT.read_text(encoding="utf-8"), re.MULTILINE
).group(1)

setup(
    name="microguard",
    version=_VERSION,
    description="CLI bot traffic audit tool powered by micrograd",
    author="Microguard",
    license="MIT",
    packages=find_packages(),
    # The built dashboard SPA ships inside the package, so `microguard
    # dashboard` works from a plain pip install with no Node involved.
    package_data={"microguard": ["dashboard/static/*", "dashboard/static/**/*"]},
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "micrograd",
    ],
    extras_require={
        # 5.0.1 annotates Redis.from_url as returning None, so every client
        # built from a URL types as None and mypy fails across microguard/live.
        # 5.0.2 fixed the annotation.
        "live": ["redis>=5.0.2,<6"],
        "fastapi": ["fastapi>=0.110", "uvicorn>=0.29"],
        "dashboard": [
            "fastapi>=0.110",
            "uvicorn>=0.29",
            "python-multipart>=0.0.9",
            "sse-starlette>=2.1",
        ],
        "flask": ["flask>=3.0"],
        "mlflow": ["mlflow>=2.10,<3"],
    },
    entry_points={
        "console_scripts": [
            "microguard=microguard.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
