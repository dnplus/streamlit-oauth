import setuptools
from pathlib import Path

README = (Path(__file__).parent/"README.md").read_text(encoding="utf8")

setuptools.setup(
    name="streamlit-oauth",
    version="0.1.7",
    author="Dylan Lu",
    author_email="dnplus@gmail.com",
    description="Simple OAuth2 authorization code flow for Streamlit",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/dnplus/streamlit-oauth",
    packages=setuptools.find_packages(),
    include_package_data=True,
    classifiers=[],
    python_requires=">=3.9",
    license_files=("LICENSE",),
    install_requires=[
        # By definition, a Custom Component depends on Streamlit.
        # If your component has other Python dependencies, list
        # them here.
        "streamlit>=1.28.0",
        "httpx-oauth>=0.4.0",
        "python-dotenv>=1.0.0"
    ],
)