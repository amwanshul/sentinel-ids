from setuptools import setup, find_packages

setup(
    name="sentinel-ids",
    version="0.1.0",
    description="Real-time network packet analyzer and intrusion detection engine",
    author="Anshul Wankhede",
    packages=find_packages(),
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "sentinel-ids=sentinel_ids.cli:main",
        ],
    },
)
