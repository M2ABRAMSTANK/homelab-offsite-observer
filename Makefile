.PHONY: test check demo syntax-check
test:
	python3 -B -m unittest discover -s tests -v
check: test
	git diff --check
demo:
	python3 -B -m observer --config config.telegram.example.json
	python3 -B -m observer --config config.example.json
syntax-check:
	ANSIBLE_CONFIG=deploy/ansible.cfg ansible-playbook -i deploy/inventory.local.yml deploy/install.yml --syntax-check
	ANSIBLE_CONFIG=deploy/ansible.cfg ansible-playbook -i deploy/inventory.local.yml deploy/activate.yml --syntax-check
	ANSIBLE_CONFIG=deploy/ansible.cfg ansible-playbook -i deploy/inventory.local.yml deploy/canary.yml --syntax-check
