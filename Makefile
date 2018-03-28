init:
	pip install pipenv
	pipenv install --dev

test:
	py.test tests

run:
	pipenv run python router_guard.py

PHONY: init run test
