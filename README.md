# V2GEvil

This project will serve as an evaluation tool for V2G communication between a car and a station. It mainly focuses on the part of the communication from and to the car.

In the futrue there will be two parts:
- Evil car: to exploit stations
- Evil station: to exploit cars

## How to make it running
~~I use pip in combination with pyproject.toml. I also use the pyenv with virtualenv plugin to manage Python version and dependencies.~~

I use poetry together with pyproject.toml. Steps are belo2 this section.

Starting with PEP 621, the Python community selected pyproject.toml as a standard way of specifying project metadata [Setuptools pyproject config](https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html).

### ~~Old Steps~~
#### 1. ~~Clone this repository~~
#### 2. ~~cd to the repository~~
#### 3. ~~Use pyenv virtualenv to create virtualenv for this project~~
```bash
# $VERSION - specific version of Python, recommended 3.10.12
VERSION="3.10.12"
NAME="V2GEvil"

V2GEvil:~/V2GEvil$ pyenv install "$VERSION"
V2GEvil:~/V2GEvil$ pyenv virtualenv "$VERSION" "$NAME"
V2GEvil:~/V2GEvil$ pyenv activate "$NAME"

```
#### 4. ~~Install it as package~~
```bash

# Virtualevn is activated
(V2GEvil) V2GEvil:~/V2GEvil$ pip3 install -e . # For development
(V2GEvil) V2GEvil:~/V2GEvil$ pip3 install . # Normal install
```

I changed my strategy because it's not working. The virtualenv in pyenv is sometimes broken...
I had to move to use poetry.
I use pyenv for managing python version and poetry as dependency resolver and virtual environment
for the isolation from the system.

### New Steps - development
#### 1. Clone this repository
#### 2. cd to the repository
#### 3. Use pyenv to manage python versions
```bash
VERSION="3.10.12"

V2GEvil:~/V2GEvil$ pyenv install "$VERSION"
V2GEvil:~/V2GEvil$ pyenv local $VERSION
```
#### 4. Install poetry
#### 5. Execute following commands
```bash
V2GEvil:~/V2GEvil$ poetry install
V2GEvil:~/V2GEvil$ poetry shell
(v2gevil-py3.10) V2GEvil:~/V2GEvil$ v2gevil
```

### New Steps - production
#### 1. Download .whl file from "dist" directory
#### 2. Install using pip (pip3, python3 -m)
```bash
V2GEvil:~/V2GEvil$ pip install v2gevil-0.1.0-py3-none-any.whl
```

Sudo command has to be used for life sniffing.
One possible approach is following:
1. Download .whl file from "dist" directory
2. Use: 'sudo pip3 install v2gevil-0.1.0-py3-none-any.whl'
3. Run: 'sudo v2gevil --help'

There are also other possibilities how it can be done.
They will not be describe here.

## Usage
```bash
# Name can be changed in pyproject.toml -> [tool.poetry.scripts]
(v2gevil-py3.10) V2GEvil:~/V2GEvil$ v2gevil --help
```


## Documentation
I will use [mkdocs materials](https://squidfunk.github.io/mkdocs-material/getting-started/) for the documentation purposes.
