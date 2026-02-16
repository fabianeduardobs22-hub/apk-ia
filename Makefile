PYTHON ?= python3

.PHONY: install install-linux quickstart test run gui lint package-deb

install:
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e .

install-linux:
	bash install_decktroy_linux.sh

quickstart:
	bash run_sentinel_x.sh

test:
	pytest -q

run:
	sentinel-x --config sentinel_x.yaml run --max-packets 200

gui:
	sentinel-x --config sentinel_x.yaml gui

package-deb:
	bash packaging/build_deb.sh
