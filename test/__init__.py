# Regular package on purpose: without this file, test/ is a namespace package and the
# stdlib's own `test` package wins the sys.path scan on pythons that ship it, so
# `python3 -m unittest test.test_foo` fails with ModuleNotFoundError. The documented
# `python3 -m unittest discover -s test` works either way.
