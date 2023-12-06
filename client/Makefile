
run:
	. ./venv/bin/activate && python taxi_congestion_sim.py

freeze:
	. ./venv/bin/activate && pip freeze -l > requirements.txt

venv:
	python3 -m virtualenv venv
	. ./venv/bin/activate && pip install -r ./requirements.txt

install-requirements:
	. ./venv/bin/activate && pip install -r ./requirements.txt
